package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
	"github.com/snehal1112/password-manager/internal/auth"
	"github.com/spf13/viper"
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/store/memory"
)

func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logrus.WithFields(logrus.Fields{
			"method": r.Method,
			"path":   r.URL.Path,
			"remote": r.RemoteAddr,
		}).Info("Received API request")
		next.ServeHTTP(w, r)
	})
}

func RateLimitMiddleware(next http.Handler) http.Handler {
	store := memory.NewStore()
	rate, _ := limiter.NewRateFromFormatted("10-M") // 10 requests per minute
	limiterInstance := limiter.New(store, rate)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if _, err := limiterInstance.Get(ctx, r.RemoteAddr); err != nil {
			logrus.Warn("Rate limit exceeded for ", r.RemoteAddr)
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			logrus.Warn("Missing Authorization header")
			http.Error(w, "Unauthorized: Missing Authorization header", http.StatusUnauthorized)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			logrus.Warn("Invalid Authorization header format")
			http.Error(w, "Unauthorized: Invalid Authorization header format", http.StatusUnauthorized)
			return
		}

		tokenString := parts[1]
		logrus.WithFields(logrus.Fields{
			"token_prefix": tokenString[:10] + "...",
			"path":         r.URL.Path,
		}).Debug("Parsing JWT")

		token, err := jwt.ParseWithClaims(tokenString, &auth.Claims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				logrus.Warn("Unexpected signing method: ", token.Header["alg"])
				return nil, jwt.ErrSignatureInvalid
			}

			var jwtSecret = viper.GetString("auth.jwt_secret")
			if jwtSecret == "" {
				logrus.Error("JWT secret is empty")
				return nil, jwt.ErrSignatureInvalid
			}

			return []byte(jwtSecret), nil
		})

		logrus.WithField("tokens", token).Debugln("after parsing ")
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err,
			}).Warn("Invalid JWT")
			http.Error(w, "Unauthorized: Invalid JWT", http.StatusUnauthorized)
			return
		}

		if !token.Valid {
			logrus.Warn("Invalid JWT: token is invalid")
			http.Error(w, "Unauthorized: Invalid JWT", http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(*auth.Claims)
		if !ok {
			logrus.Warn("Invalid JWT claims")
			http.Error(w, "Unauthorized: Invalid JWT claims", http.StatusUnauthorized)
			return
		}

		logrus.WithFields(logrus.Fields{
			"user_id":  claims.UserID,
			"username": claims.Username,
			"role":     claims.Role,
		}).Debug("JWT validated")

		ctx := context.WithValue(r.Context(), "user", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
