package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/TBuckholz5/bookshelf/internal/util/jwt"
)

type ctxKey struct {
	name string
}

var CtxKeyUserID = ctxKey{"userID"}

type AuthMiddleware struct {
	JwtService jwt.JwtService
}

func NewAuthMiddleware(jwtService jwt.JwtService) *AuthMiddleware {
	return &AuthMiddleware{
		JwtService: jwtService,
	}
}

func (a *AuthMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(authHeader, prefix) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		authHeader = strings.TrimSpace(strings.TrimPrefix(authHeader, prefix))
		userID, err := a.JwtService.ValidateJwt(authHeader)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), CtxKeyUserID, userID)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}
