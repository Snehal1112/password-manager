package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"rocketvault/internal/signing"
)

// JWTClaims represents the claims structure for JWT tokens.
// It extends the standard JWT claims with user-specific information
// required for authentication and authorization.
type JWTClaims struct {
	UserID   uuid.UUID `json:"user_id"`
	Username string    `json:"username"`
	Role     string    `json:"role"`
	jwt.RegisteredClaims
}

// JWTService handles JWT token creation and validation operations.
type JWTService interface {
	GenerateToken(userID uuid.UUID, username, role string, sessionID uuid.UUID) (string, error)
	ValidateToken(tokenString string) (*JWTClaims, error)
	ParseToken(tokenString string) (*JWTClaims, error)
}

// jwtService uses an asymmetric SigningKeyProvider for signing.
type jwtService struct {
	provider          signing.SigningKeyProvider
	issuer            string
	audience          string
	expiry            time.Duration
	logger            *logrus.Logger
	// HS256 fallback fields — both nil/zero after migration window expires.
	hs256SecretKey    []byte
	migrationDeadline time.Time
}

// legacyJWTService is the original HS256-only implementation kept for the migration path.
type legacyJWTService struct {
	secretKey []byte
	issuer    string
	audience  string
	expiry    time.Duration
	logger    *logrus.Logger
}

// JWTConfig holds configuration for JWT service.
type JWTConfig struct {
	SecretKey       string
	Issuer          string
	Audience        string
	Expiry          time.Duration
	MigrationWindow time.Duration // HS256 fallback window after upgrade; 0 = no fallback
	Logger          *logrus.Logger
}

// NewJWTServiceWithProvider creates a JWT service backed by an asymmetric signing provider.
// If config.SecretKey is set and config.MigrationWindow > 0 the service accepts legacy
// HS256 tokens until the window elapses.
func NewJWTServiceWithProvider(config JWTConfig, provider signing.SigningKeyProvider) JWTService {
	logger := config.Logger
	if logger == nil {
		logger = logrus.StandardLogger()
	}
	svc := &jwtService{
		provider: provider,
		issuer:   config.Issuer,
		audience: config.Audience,
		expiry:   config.Expiry,
		logger:   logger,
	}
	if config.SecretKey != "" && config.MigrationWindow > 0 {
		svc.hs256SecretKey = []byte(config.SecretKey)
		svc.migrationDeadline = time.Now().Add(config.MigrationWindow)
	}
	return svc
}

// NewJWTService creates the legacy HS256 JWT service.
// Kept for backward compatibility during migration — remove after migration window support is dropped.
func NewJWTService(config JWTConfig) JWTService {
	logger := config.Logger
	if logger == nil {
		logger = logrus.StandardLogger()
	}
	return &legacyJWTService{
		secretKey: []byte(config.SecretKey),
		issuer:    config.Issuer,
		audience:  config.Audience,
		expiry:    config.Expiry,
		logger:    logger,
	}
}

// GenerateToken signs a new JWT using the asymmetric provider (RS256 or ES256).
func (s *jwtService) GenerateToken(userID uuid.UUID, username, role string, sessionID uuid.UUID) (string, error) {
	now := time.Now()
	claims := JWTClaims{
		UserID:   userID,
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        sessionID.String(),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.expiry)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    s.issuer,
			Subject:   userID.String(),
			Audience:  jwt.ClaimStrings{s.audience},
		},
	}

	var signingMethod jwt.SigningMethod
	switch s.provider.Algorithm() {
	case "RS256":
		signingMethod = jwt.SigningMethodRS256
	case "ES256":
		signingMethod = jwt.SigningMethodES256
	case "ES384":
		signingMethod = jwt.SigningMethodES384
	case "ES512":
		signingMethod = jwt.SigningMethodES512
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", s.provider.Algorithm())
	}

	token := jwt.NewWithClaims(signingMethod, claims)
	token.Header["kid"] = s.provider.KeyID()

	tokenString, err := token.SignedString(s.provider.PrivateKey())
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT token: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"user_id":  userID.String(),
		"username": username,
		"kid":      s.provider.KeyID(),
		"alg":      s.provider.Algorithm(),
	}).Debug("JWT token generated")

	return tokenString, nil
}

// ValidateToken verifies a JWT. Dispatches by kid to the correct asymmetric key.
// Falls back to HS256 if kid is absent and the migration window is still active.
func (s *jwtService) ValidateToken(tokenString string) (*JWTClaims, error) {
	// Peek at the kid header without full validation.
	unverified, _, err := jwt.NewParser().ParseUnverified(tokenString, &JWTClaims{})
	if err != nil {
		return nil, fmt.Errorf("invalid JWT token: %w", err)
	}

	kid, _ := unverified.Header["kid"].(string)

	if kid == "" {
		return s.validateHS256Fallback(tokenString)
	}

	return s.validateAsymmetric(tokenString, kid)
}

func (s *jwtService) validateAsymmetric(tokenString, kid string) (*JWTClaims, error) {
	var matchedKey interface{}
	for _, info := range s.provider.PublicKeys() {
		if info.KeyID == kid {
			matchedKey = info.PublicKey
			break
		}
	}
	if matchedKey == nil {
		return nil, fmt.Errorf("unknown kid: %q", kid)
	}

	claims := &JWTClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if err := s.validateCommonClaims(claims); err != nil {
			return nil, err
		}
		return matchedKey, nil
	})
	if err != nil {
		s.logger.WithError(err).Error("JWT asymmetric validation failed")
		return nil, fmt.Errorf("invalid JWT token: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid JWT token")
	}
	return token.Claims.(*JWTClaims), nil
}

func (s *jwtService) validateHS256Fallback(tokenString string) (*JWTClaims, error) {
	if len(s.hs256SecretKey) == 0 || time.Now().After(s.migrationDeadline) {
		return nil, fmt.Errorf("token uses deprecated signing algorithm — HS256 migration window expired")
	}

	s.logger.Warn("HS256 token accepted — migration window active")

	claims := &JWTClaims{}
	secretKey := s.hs256SecretKey
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		if err := s.validateCommonClaims(claims); err != nil {
			return nil, err
		}
		return secretKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid JWT token: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid JWT token")
	}
	return token.Claims.(*JWTClaims), nil
}

func (s *jwtService) validateCommonClaims(claims *JWTClaims) error {
	if claims.Issuer != s.issuer {
		return fmt.Errorf("invalid issuer")
	}
	for _, a := range claims.Audience {
		if a == s.audience {
			return nil
		}
	}
	return fmt.Errorf("invalid audience")
}

// ParseToken parses a token without signature verification (inspection only).
func (s *jwtService) ParseToken(tokenString string) (*JWTClaims, error) {
	claims := &JWTClaims{}
	token, _, err := jwt.NewParser().ParseUnverified(tokenString, claims)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT token: %w", err)
	}
	parsed, ok := token.Claims.(*JWTClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims type")
	}
	return parsed, nil
}

// --- legacyJWTService (HS256 only) ---

func (s *legacyJWTService) GenerateToken(userID uuid.UUID, username, role string, sessionID uuid.UUID) (string, error) {
	now := time.Now()
	claims := JWTClaims{
		UserID:   userID,
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        sessionID.String(),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.expiry)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    s.issuer,
			Subject:   userID.String(),
			Audience:  jwt.ClaimStrings{s.audience},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(s.secretKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT token: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"user_id":  userID.String(),
		"username": username,
		"role":     role,
	}).Debug("JWT token generated successfully")

	return tokenString, nil
}

func (s *legacyJWTService) ValidateToken(tokenString string) (*JWTClaims, error) {
	claims := &JWTClaims{}
	secretKey := s.secretKey
	issuer := s.issuer
	audience := s.audience

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			s.logger.WithField("alg", token.Header["alg"]).Warn("Unexpected JWT signing method")
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		if claims.Issuer != issuer {
			s.logger.WithFields(logrus.Fields{"expected": issuer, "actual": claims.Issuer}).Warn("JWT issuer mismatch")
			return nil, fmt.Errorf("invalid issuer")
		}
		for _, a := range claims.Audience {
			if a == audience {
				return secretKey, nil
			}
		}
		s.logger.WithFields(logrus.Fields{"expected": audience, "actual": claims.Audience}).Warn("JWT audience mismatch")
		return nil, fmt.Errorf("invalid audience")
	})
	if err != nil {
		s.logger.WithError(err).Error("JWT token validation failed")
		return nil, fmt.Errorf("invalid JWT token: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid JWT token")
	}
	validClaims, ok := token.Claims.(*JWTClaims)
	if !ok {
		return nil, fmt.Errorf("invalid JWT claims")
	}
	return validClaims, nil
}

func (s *legacyJWTService) ParseToken(tokenString string) (*JWTClaims, error) {
	claims := &JWTClaims{}
	token, _, err := jwt.NewParser().ParseUnverified(tokenString, claims)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT token: %w", err)
	}
	parsed, ok := token.Claims.(*JWTClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims type")
	}
	return parsed, nil
}
