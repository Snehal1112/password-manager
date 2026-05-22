package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
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
// It provides secure token management for user sessions,
// separating JWT concerns from other authentication logic.
type JWTService interface {
	GenerateToken(userID uuid.UUID, username, role string) (string, error)
	ValidateToken(tokenString string) (*JWTClaims, error)
	ParseToken(tokenString string) (*JWTClaims, error)
}

// jwtService implements JWTService for JWT token operations.
type jwtService struct {
	secretKey []byte
	issuer    string
	audience  string
	expiry    time.Duration
	logger    *logrus.Logger
}

// JWTConfig holds configuration for JWT service.
type JWTConfig struct {
	SecretKey string
	Issuer    string
	Audience  string
	Expiry    time.Duration
	// Logger is the logrus instance to use. Falls back to the global logger when nil.
	Logger *logrus.Logger
}

// NewJWTService creates a new JWTService with the provided configuration.
// It initializes the service with signing key, issuer information,
// and token expiration settings.
//
// Parameters:
//
//	config: JWT configuration including secret key and metadata.
//
// Returns:
//
//	A JWTService implementation for token operations.
func NewJWTService(config JWTConfig) JWTService {
	logger := config.Logger
	if logger == nil {
		logger = logrus.StandardLogger()
	}
	return &jwtService{
		secretKey: []byte(config.SecretKey),
		issuer:    config.Issuer,
		audience:  config.Audience,
		expiry:    config.Expiry,
		logger:    logger,
	}
}

// GenerateToken creates a new JWT token for a user session.
// It includes user identification, role information, and standard
// JWT claims with appropriate expiration and metadata.
//
// Parameters:
//
//	userID: The user's unique identifier.
//	username: The user's username.
//	role: The user's role for authorization.
//
// Returns:
//
//	The signed JWT token string and an error if generation fails.
func (s *jwtService) GenerateToken(userID uuid.UUID, username, role string) (string, error) {
	now := time.Now()
	claims := JWTClaims{
		UserID:   userID,
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
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

// ValidateToken validates a JWT token and returns the claims if valid.
// It performs comprehensive validation including signature verification,
// expiration checks, and claim validation.
//
// Parameters:
//
//	tokenString: The JWT token string to validate.
//
// Returns:
//
//	The parsed and validated claims and an error if validation fails.
func (s *jwtService) ValidateToken(tokenString string) (*JWTClaims, error) {
	claims := &JWTClaims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method — prevents alg=none and RS→HS confusion attacks.
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			s.logger.WithField("alg", token.Header["alg"]).Warn("Unexpected JWT signing method")
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Validate issuer.
		if claims.Issuer != s.issuer {
			s.logger.WithFields(logrus.Fields{
				"expected": s.issuer,
				"actual":   claims.Issuer,
			}).Warn("JWT issuer mismatch")
			return nil, fmt.Errorf("invalid issuer")
		}

		// Validate audience — RFC 7519 §4.1.3 MUST: reject tokens not intended for this server.
		audValid := false
		for _, a := range claims.Audience {
			if a == s.audience {
				audValid = true
				break
			}
		}
		if !audValid {
			s.logger.WithFields(logrus.Fields{
				"expected": s.audience,
				"actual":   claims.Audience,
			}).Warn("JWT audience mismatch")
			return nil, fmt.Errorf("invalid audience")
		}

		return s.secretKey, nil
	})
	if err != nil {
		s.logger.WithError(err).Error("JWT token validation failed")
		return nil, fmt.Errorf("invalid JWT token: %w", err)
	}

	if !token.Valid {
		s.logger.Error("JWT token is invalid")
		return nil, fmt.Errorf("invalid JWT token")
	}

	validClaims, ok := token.Claims.(*JWTClaims)
	if !ok {
		s.logger.Error("Invalid JWT claims type")
		return nil, fmt.Errorf("invalid JWT claims")
	}

	return validClaims, nil
}

// ParseToken parses a JWT token without full validation.
// This method extracts claims from a token for inspection purposes
// but should not be used for authentication decisions.
//
// Parameters:
//
//	tokenString: The JWT token string to parse.
//
// Returns:
//
//	The parsed claims and an error if parsing fails.
func (s *jwtService) ParseToken(tokenString string) (*JWTClaims, error) {
	claims := &JWTClaims{}

	// Parse without validation for inspection
	token, _, err := jwt.NewParser().ParseUnverified(tokenString, claims)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT token: %w", err)
	}

	parsedClaims, ok := token.Claims.(*JWTClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims type")
	}

	return parsedClaims, nil
}
