package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/TBuckholz5/bookshelf/internal/util/jwt"
)

type AuthMiddleware struct {
	jwtService jwt.JwtService
}

func NewAuthMiddleware(jwtService jwt.JwtService) *AuthMiddleware {
	return &AuthMiddleware{
		jwtService: jwtService,
	}
}

// Validates the caller's JWT token and underlying session.
// Checks for JWT validity and session revokation or expiration.
func (a *AuthMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(authHeader, prefix) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		authHeader = strings.TrimSpace(strings.TrimPrefix(authHeader, prefix))
		claims, err := a.jwtService.ValidateJwt(authHeader)
		if err != nil {
			http.Error(w, "JWT not valid", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), CtxKeyClaims, claims)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}
