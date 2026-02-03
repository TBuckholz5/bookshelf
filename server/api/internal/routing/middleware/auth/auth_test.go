package auth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/TBuckholz5/bookshelf/internal/util/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type mockService struct {
	mock.Mock
}

func (m *mockService) GenerateJwt(claims jwt.JwtClaims) (string, error) {
	args := m.Called(claims)
	return args.String(0), args.Error(1)
}

func (m *mockService) ValidateJwt(tokenString string) (jwt.JwtClaims, error) {
	args := m.Called(tokenString)
	return args.Get(0).(jwt.JwtClaims), args.Error(1)
}

func TestAuthMiddleware_Success(t *testing.T) {
	var (
		mockServiceInstance = &mockService{}
		middleware          = NewAuthMiddleware(mockServiceInstance)
	)
	claims := jwt.JwtClaims{
		SessionID: "session_test",
		UserID:    "user_test",
		Expiry:    time.Now(),
		Issuer:    "bookshelf",
	}
	mockServiceInstance.On("ValidateJwt", mock.Anything).Return(claims, nil)

	req, err := http.NewRequest("GET", "/protected", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer validtoken")

	rr := httptest.NewRecorder()
	mockHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		assert.Equal(t, claims, r.Context().Value(CtxKeyClaims))
	}
	handler := middleware.Wrap(http.HandlerFunc(mockHandler))

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
}

func TestAuthMiddleware_NoBearerPrefix(t *testing.T) {
	var (
		mockServiceInstance = &mockService{}
		middleware          = NewAuthMiddleware(mockServiceInstance)
	)
	mockServiceInstance.On("ValidateJwt", mock.Anything).Return(jwt.JwtClaims{}, nil)

	req, err := http.NewRequest("GET", "/protected", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "invalidformat")

	rr := httptest.NewRecorder()
	mockHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
	handler := middleware.Wrap(http.HandlerFunc(mockHandler))

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusUnauthorized)
	}
}

func TestAuthMiddleware_AuthError(t *testing.T) {
	var (
		mockServiceInstance = &mockService{}
		middleware          = NewAuthMiddleware(mockServiceInstance)
	)
	mockServiceInstance.On("ValidateJwt", mock.Anything).Return(jwt.JwtClaims{}, fmt.Errorf("invalid token"))

	req, err := http.NewRequest("GET", "/protected", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer invalid")

	rr := httptest.NewRecorder()
	mockHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
	handler := middleware.Wrap(http.HandlerFunc(mockHandler))

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusUnauthorized)
	}
}
