package auth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type mockService struct {
	mock.Mock
}

func (m *mockService) GenerateJwt(userID string, exp time.Time) (string, error) {
	args := m.Called(userID)
	return args.String(0), args.Error(1)
}

func (m *mockService) ValidateJwt(tokenString string) (string, error) {
	args := m.Called(tokenString)
	return args.Get(0).(string), args.Error(1)
}

func TestAuthMiddleware_Success(t *testing.T) {
	var (
		mockServiceInstance = &mockService{}
		middleware          = NewAuthMiddleware(mockServiceInstance)
	)
	mockServiceInstance.On("ValidateJwt", mock.Anything).Return("token", nil)

	req, err := http.NewRequest("GET", "/protected", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer validtoken")

	rr := httptest.NewRecorder()
	mockHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		assert.Equal(t, "token", r.Context().Value(CtxKeyUserID))
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
	mockServiceInstance.On("ValidateJwt", mock.Anything).Return("token", nil)

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
	mockServiceInstance.On("ValidateJwt", mock.Anything).Return("token", fmt.Errorf("invalid token"))

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
