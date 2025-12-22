package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TBuckholz5/bookshelf/internal/domains/auth/models"
	"github.com/TBuckholz5/bookshelf/internal/domains/auth/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/oauth2"
)

type mockGoogleOAuth struct {
	mock.Mock
}

func (g *mockGoogleOAuth) AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string {
	args := g.Called(state, opts)
	return args.String(0)
}

func (g *mockGoogleOAuth) Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	args := g.Called(ctx, code, opts)
	return args.Get(0).(*oauth2.Token), args.Error(1)
}

type mockHttpClient struct {
	mock.Mock
}

func (h *mockHttpClient) Get(url string) (resp *http.Response, err error) {
	args := h.Called(url)
	return args.Get(0).(*http.Response), args.Error(1)
}

type mockService struct {
	mock.Mock
}

func (s *mockService) Login(req models.UserLoginRequestInfo) (models.UserLoginResponse, error) {
	args := s.Called(req)
	return args.Get(0).(models.UserLoginResponse), args.Error(1)
}

func (s *mockService) Refresh(refreshToken string) (models.UserLoginResponse, error) {
	args := s.Called(refreshToken)
	return args.Get(0).(models.UserLoginResponse), args.Error(1)
}

func Test_GoogleLoginCallbackSuccess(t *testing.T) {
	mockGoogleOAuthInstance := &mockGoogleOAuth{}
	mockGoogleOAuthInstance.On("Exchange", mock.Anything, mock.Anything, mock.Anything).Return(&oauth2.Token{
		AccessToken:  "testoauthaccesstoken",
		RefreshToken: "testoauthrefreshtoken",
	}, nil)

	mockHttpClientInstance := &mockHttpClient{}
	mockHttpClientInstance.On("Get", mock.Anything).Return(&http.Response{
		Body: io.NopCloser(strings.NewReader(
			`{"id":"testid", "email": "testemail", "name": "testname"}`)),
	}, nil)

	mockServiceInstance := &mockService{}
	mockAccessToken := "testaccesstoken"
	mockRefreshToken := "testrefreshtoken"
	mockServiceInstance.On("Login", mock.Anything).Return(models.UserLoginResponse{
		AccessToken:  mockAccessToken,
		RefreshToken: mockRefreshToken,
	}, nil)

	req := httptest.NewRequest(
		http.MethodPost,
		fmt.Sprintf("/callback?state=%s", oAuthState),
		nil,
	)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(NewAuthController(mockServiceInstance,
		mockGoogleOAuthInstance, mockHttpClientInstance).GoogleCallback)
	handler.ServeHTTP(rr, req)

	mock.AssertExpectationsForObjects(t, mockServiceInstance, mockGoogleOAuthInstance, mockHttpClientInstance)

	// Check status.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check response body.
	responseBodyBytes, err := io.ReadAll(rr.Body)
	if err != nil {
		t.Fatal(err)
	}
	var responsePayload models.UserLoginResponse
	if err := json.Unmarshal(responseBodyBytes, &responsePayload); err != nil {
		t.Errorf("could not decode response body: %v", err)
	}

	assert.Equal(t, responsePayload.AccessToken, mockAccessToken)
	assert.Equal(t, responsePayload.RefreshToken, mockRefreshToken)
}

func Test_GoogleLoginCallbackStateMismatchError(t *testing.T) {
	req := httptest.NewRequest(
		http.MethodPost,
		fmt.Sprintf("/callback?state=%s", "random"),
		nil,
	)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(NewAuthController(nil,
		nil, nil).GoogleCallback)
	handler.ServeHTTP(rr, req)

	// Check status.
	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
}

func Test_GoogleLoginCallbackExchangeError(t *testing.T) {
	mockGoogleOAuthInstance := &mockGoogleOAuth{}
	mockGoogleOAuthInstance.On("Exchange", mock.Anything, mock.Anything, mock.Anything).Return(&oauth2.Token{}, fmt.Errorf("error"))

	req := httptest.NewRequest(
		http.MethodPost,
		fmt.Sprintf("/callback?state=%s", oAuthState),
		nil,
	)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(NewAuthController(nil,
		mockGoogleOAuthInstance, nil).GoogleCallback)
	handler.ServeHTTP(rr, req)

	mock.AssertExpectationsForObjects(t, mockGoogleOAuthInstance)

	// Check status.
	if status := rr.Code; status != http.StatusInternalServerError {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
}

func Test_GoogleLoginCallbackOAuthGetError(t *testing.T) {
	mockGoogleOAuthInstance := &mockGoogleOAuth{}
	mockGoogleOAuthInstance.On("Exchange", mock.Anything, mock.Anything, mock.Anything).Return(&oauth2.Token{
		AccessToken:  "testoauthaccesstoken",
		RefreshToken: "testoauthrefreshtoken",
	}, nil)

	mockHttpClientInstance := &mockHttpClient{}
	mockHttpClientInstance.On("Get", mock.Anything).Return(&http.Response{}, fmt.Errorf("error"))

	req := httptest.NewRequest(
		http.MethodPost,
		fmt.Sprintf("/callback?state=%s", oAuthState),
		nil,
	)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(NewAuthController(nil,
		mockGoogleOAuthInstance, mockHttpClientInstance).GoogleCallback)
	handler.ServeHTTP(rr, req)

	mock.AssertExpectationsForObjects(t, mockGoogleOAuthInstance, mockHttpClientInstance)

	// Check status.
	if status := rr.Code; status != http.StatusInternalServerError {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
}

func Test_GoogleLoginCallbackOAuthGetUnMarshalError(t *testing.T) {
	mockGoogleOAuthInstance := &mockGoogleOAuth{}
	mockGoogleOAuthInstance.On("Exchange", mock.Anything, mock.Anything, mock.Anything).Return(&oauth2.Token{
		AccessToken:  "testoauthaccesstoken",
		RefreshToken: "testoauthrefreshtoken",
	}, nil)

	mockHttpClientInstance := &mockHttpClient{}
	mockHttpClientInstance.On("Get", mock.Anything).Return(&http.Response{
		Body: io.NopCloser(strings.NewReader(
			`{"id":"testid", "email": "testemail, "name": "testname"}`)),
	}, nil)

	req := httptest.NewRequest(
		http.MethodPost,
		fmt.Sprintf("/callback?state=%s", oAuthState),
		nil,
	)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(NewAuthController(nil,
		mockGoogleOAuthInstance, mockHttpClientInstance).GoogleCallback)
	handler.ServeHTTP(rr, req)

	mock.AssertExpectationsForObjects(t, mockGoogleOAuthInstance, mockHttpClientInstance)

	// Check status.
	if status := rr.Code; status != http.StatusInternalServerError {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
}

func Test_GoogleLoginCallbackServiceError(t *testing.T) {
	mockGoogleOAuthInstance := &mockGoogleOAuth{}
	mockGoogleOAuthInstance.On("Exchange", mock.Anything, mock.Anything, mock.Anything).Return(&oauth2.Token{
		AccessToken:  "testoauthaccesstoken",
		RefreshToken: "testoauthrefreshtoken",
	}, nil)

	mockHttpClientInstance := &mockHttpClient{}
	mockHttpClientInstance.On("Get", mock.Anything).Return(&http.Response{
		Body: io.NopCloser(strings.NewReader(
			`{"id":"testid", "email": "testemail", "name": "testname"}`)),
	}, nil)

	mockServiceInstance := &mockService{}
	mockServiceInstance.On("Login", mock.Anything).Return(models.UserLoginResponse{}, fmt.Errorf("error"))

	req := httptest.NewRequest(
		http.MethodPost,
		fmt.Sprintf("/callback?state=%s", oAuthState),
		nil,
	)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(NewAuthController(mockServiceInstance,
		mockGoogleOAuthInstance, mockHttpClientInstance).GoogleCallback)
	handler.ServeHTTP(rr, req)

	mock.AssertExpectationsForObjects(t, mockGoogleOAuthInstance, mockHttpClientInstance)

	// Check status.
	if status := rr.Code; status != http.StatusInternalServerError {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
}

func Test_RefreshSuccess(t *testing.T) {
	mockServiceInstance := &mockService{}
	updatedTokens := models.UserLoginResponse{
		AccessToken:  "testaccesstoken",
		RefreshToken: "testupdatedrefreshtoken",
	}
	mockServiceInstance.On("Refresh", mock.Anything).Return(updatedTokens, nil)

	initialRefreshToken := "testinitrefreshtoken"
	req := httptest.NewRequest(
		http.MethodPost,
		"/refresh",
		strings.NewReader(fmt.Sprintf(`{"refreshToken": "%s"}`, initialRefreshToken)),
	)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(NewAuthController(mockServiceInstance,
		nil, nil).RefreshSession)
	handler.ServeHTTP(rr, req)

	mock.AssertExpectationsForObjects(t, mockServiceInstance)

	// Check status.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check response body.
	responseBodyBytes, err := io.ReadAll(rr.Body)
	if err != nil {
		t.Fatal(err)
	}
	var responsePayload models.UserLoginResponse
	if err := json.Unmarshal(responseBodyBytes, &responsePayload); err != nil {
		t.Errorf("could not decode response body: %v", err)
	}

	assert.Equal(t, responsePayload.AccessToken, updatedTokens.AccessToken)
	assert.Equal(t, responsePayload.RefreshToken, updatedTokens.RefreshToken)
}

func Test_RefreshMalformedBodyError(t *testing.T) {
	initialRefreshToken := "testinitrefreshtoken"
	req := httptest.NewRequest(
		http.MethodPost,
		"/refresh",
		strings.NewReader(fmt.Sprintf(`{refreshToken": %s"}`, initialRefreshToken)),
	)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(NewAuthController(nil,
		nil, nil).RefreshSession)
	handler.ServeHTTP(rr, req)

	// Check status.
	if status := rr.Code; status != http.StatusInternalServerError {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
}

func Test_RefreshServiceUnauthError(t *testing.T) {
	mockServiceInstance := &mockService{}
	mockServiceInstance.On("Refresh", mock.Anything).Return(
		models.UserLoginResponse{}, service.NewUnauthorizedError("error"))

	initialRefreshToken := "testinitrefreshtoken"
	req := httptest.NewRequest(
		http.MethodPost,
		"/refresh",
		strings.NewReader(fmt.Sprintf(`{"refreshToken": "%s"}`, initialRefreshToken)),
	)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(NewAuthController(mockServiceInstance,
		nil, nil).RefreshSession)
	handler.ServeHTTP(rr, req)

	mock.AssertExpectationsForObjects(t, mockServiceInstance)

	// Check status.
	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
}

func Test_RefreshServiceInternalError(t *testing.T) {
	mockServiceInstance := &mockService{}
	mockServiceInstance.On("Refresh", mock.Anything).Return(
		models.UserLoginResponse{}, service.NewInternalError("error"))

	initialRefreshToken := "testinitrefreshtoken"
	req := httptest.NewRequest(
		http.MethodPost,
		"/refresh",
		strings.NewReader(fmt.Sprintf(`{"refreshToken": "%s"}`, initialRefreshToken)),
	)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(NewAuthController(mockServiceInstance,
		nil, nil).RefreshSession)
	handler.ServeHTTP(rr, req)

	mock.AssertExpectationsForObjects(t, mockServiceInstance)

	// Check status.
	if status := rr.Code; status != http.StatusInternalServerError {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusInternalServerError)
	}
}
