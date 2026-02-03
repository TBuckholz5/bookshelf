package service

import (
	"fmt"
	"testing"
	"time"

	"github.com/TBuckholz5/bookshelf/internal/domains/auth/models"
	"github.com/TBuckholz5/bookshelf/internal/domains/auth/repository"
	"github.com/TBuckholz5/bookshelf/internal/util/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/oauth2"
)

type mockRepository struct {
	mock.Mock
}

func (r *mockRepository) UpsertUser(req *repository.UpsertUserRequest) (*repository.User, error) {
	args := r.Called(req)
	return args.Get(0).(*repository.User), args.Error(1)
}

func (r *mockRepository) CreateSession(req *repository.CreateSessionRequest) (*repository.Session, error) {
	args := r.Called(req)
	return args.Get(0).(*repository.Session), args.Error(1)
}

func (r *mockRepository) UpdateSession(req *repository.UpdateSessionRequest) error {
	args := r.Called(req)
	return args.Error(0)
}

func (r *mockRepository) GetSessionForTokenHash(tokenHash []byte) (*repository.Session, error) {
	args := r.Called(tokenHash)
	return args.Get(0).(*repository.Session), args.Error(1)
}

type mockAes struct {
	mock.Mock
}

func (a *mockAes) Encrypt(s []byte) ([]byte, error) {
	args := a.Called(s)
	return args.Get(0).([]byte), args.Error(1)
}

type mockJwt struct {
	mock.Mock
}

func (j *mockJwt) GenerateJwt(claims jwt.JwtClaims) (string, error) {
	args := j.Called(claims)
	return args.String(0), args.Error(1)
}

func (j *mockJwt) ValidateJwt(tokenString string) (jwt.JwtClaims, error) {
	args := j.Called(tokenString)
	return args.Get(0).(jwt.JwtClaims), args.Error(1)
}

var loginInput = models.UserLoginRequestInfo{
	OAuthType: "Google",
	ExternalUserInfo: &models.OAuthUserInfo{
		ID:    "id",
		Email: "email",
		Name:  "name",
	},
	Token: &oauth2.Token{
		AccessToken:  "testoauthaccesstoken",
		RefreshToken: "testoauthrefreshtoken",
	},
}

func Test_LoginSuccess(t *testing.T) {
	mockAesInstance := &mockAes{}
	testOauthAccessToken := []byte("testoauthaccesstoken")
	mockAesInstance.On("Encrypt", mock.Anything).Return(testOauthAccessToken, nil).Once()
	testOauthRefreshToken := []byte("testoauthrefreshtoken")
	mockAesInstance.On("Encrypt", mock.Anything).Return(testOauthRefreshToken, nil).Once()

	mockRepositoryInstance := &mockRepository{}
	timeNow := time.Now()
	mockUser := repository.User{
		ID:                    "testuserid",
		Email:                 "testuseremail",
		DisplayName:           "testuserdisplayname",
		OAuthProviderID:       "testoauthid",
		OAuthProviderName:     "Google",
		EncryptedAccessToken:  []byte("testoauthaccesstoken"),
		EncryptedRefreshToken: []byte("testoauthrefershtoken"),
		CreatedAt:             timeNow,
		UpdatedAt:             timeNow,
		LastLogin:             timeNow,
	}
	mockRepositoryInstance.On("UpsertUser", mock.Anything).Return(&mockUser, nil).Once()
	mockSession := repository.Session{
		ID:                    "testsessionid",
		UserID:                "testuserid",
		RefreshTokenHash:      []byte("testrefreshtoken"),
		RefreshTokenExpiresAt: timeNow,
		CreatedAt:             timeNow,
		UpdatedAt:             timeNow,
		RevokedAt:             &timeNow,
	}
	mockRepositoryInstance.On("CreateSession", mock.Anything).Return(&mockSession, nil).Once()

	mockJwtInstance := &mockJwt{}
	mockJwtAccessToken := "testjwtaccesstoken"
	mockJwtInstance.On("GenerateJwt", mock.Anything).Return(mockJwtAccessToken, nil).Once()

	actualResponse, err := NewAuthService(mockRepositoryInstance, mockJwtInstance,
		mockAesInstance).Login(loginInput)

	mock.AssertExpectationsForObjects(t, mockAesInstance, mockRepositoryInstance, mockJwtInstance)
	assert.Equal(t, err, nil)
	assert.Equal(t, actualResponse.AccessToken, mockJwtAccessToken)
	assert.NotEmpty(t, actualResponse.RefreshToken)
}

func Test_LoginAesErrorAccessToken(t *testing.T) {
	mockAesInstance := &mockAes{}
	testOauthAccessToken := []byte("testoauthaccesstoken")
	mockAesInstance.On("Encrypt", mock.Anything).Return(testOauthAccessToken, fmt.Errorf("error")).Once()

	_, err := NewAuthService(nil, nil,
		mockAesInstance).Login(loginInput)

	mock.AssertExpectationsForObjects(t, mockAesInstance)
	assert.NotEqual(t, err, nil)
}

func Test_LoginAesErrorRefreshToken(t *testing.T) {
	mockAesInstance := &mockAes{}
	testOauthAccessToken := []byte("testoauthaccesstoken")
	mockAesInstance.On("Encrypt", mock.Anything).Return(testOauthAccessToken, nil).Once()
	testOauthRefreshToken := []byte("testoauthrefreshtoken")
	mockAesInstance.On("Encrypt", mock.Anything).Return(testOauthRefreshToken, fmt.Errorf("error")).Once()

	_, err := NewAuthService(nil, nil,
		mockAesInstance).Login(loginInput)

	mock.AssertExpectationsForObjects(t, mockAesInstance)
	assert.NotEqual(t, err, nil)
}

func Test_LoginUpsertUserError(t *testing.T) {
	mockAesInstance := &mockAes{}
	testOauthAccessToken := []byte("testoauthaccesstoken")
	mockAesInstance.On("Encrypt", mock.Anything).Return(testOauthAccessToken, nil).Once()
	testOauthRefreshToken := []byte("testoauthrefreshtoken")
	mockAesInstance.On("Encrypt", mock.Anything).Return(testOauthRefreshToken, nil).Once()

	mockRepositoryInstance := &mockRepository{}
	mockRepositoryInstance.On("UpsertUser", mock.Anything).Return(
		&repository.User{}, fmt.Errorf("error")).Once()

	_, err := NewAuthService(mockRepositoryInstance, nil,
		mockAesInstance).Login(loginInput)

	mock.AssertExpectationsForObjects(t, mockAesInstance, mockRepositoryInstance)
	assert.NotEqual(t, err, nil)
}

func Test_LoginCreateSessionError(t *testing.T) {
	mockAesInstance := &mockAes{}
	testOauthAccessToken := []byte("testoauthaccesstoken")
	mockAesInstance.On("Encrypt", mock.Anything).Return(testOauthAccessToken, nil).Once()
	testOauthRefreshToken := []byte("testoauthrefreshtoken")
	mockAesInstance.On("Encrypt", mock.Anything).Return(testOauthRefreshToken, nil).Once()

	mockRepositoryInstance := &mockRepository{}
	timeNow := time.Now()
	mockUser := repository.User{
		ID:                    "testuserid",
		Email:                 "testuseremail",
		DisplayName:           "testuserdisplayname",
		OAuthProviderID:       "testoauthid",
		OAuthProviderName:     "Google",
		EncryptedAccessToken:  []byte("testoauthaccesstoken"),
		EncryptedRefreshToken: []byte("testoauthrefershtoken"),
		CreatedAt:             timeNow,
		UpdatedAt:             timeNow,
		LastLogin:             timeNow,
	}
	mockRepositoryInstance.On("UpsertUser", mock.Anything).Return(&mockUser, nil).Once()
	mockRepositoryInstance.On("CreateSession", mock.Anything).Return(&repository.Session{}, fmt.Errorf("error")).Once()

	_, err := NewAuthService(mockRepositoryInstance, nil,
		mockAesInstance).Login(loginInput)

	mock.AssertExpectationsForObjects(t, mockAesInstance, mockRepositoryInstance)
	assert.NotEqual(t, err, nil)
}

func Test_LoginJwtError(t *testing.T) {
	mockAesInstance := &mockAes{}
	testOauthAccessToken := []byte("testoauthaccesstoken")
	mockAesInstance.On("Encrypt", mock.Anything).Return(testOauthAccessToken, nil).Once()
	testOauthRefreshToken := []byte("testoauthrefreshtoken")
	mockAesInstance.On("Encrypt", mock.Anything).Return(testOauthRefreshToken, nil).Once()

	mockRepositoryInstance := &mockRepository{}
	timeNow := time.Now()
	mockUser := repository.User{
		ID:                    "testuserid",
		Email:                 "testuseremail",
		DisplayName:           "testuserdisplayname",
		OAuthProviderID:       "testoauthid",
		OAuthProviderName:     "Google",
		EncryptedAccessToken:  []byte("testoauthaccesstoken"),
		EncryptedRefreshToken: []byte("testoauthrefershtoken"),
		CreatedAt:             timeNow,
		UpdatedAt:             timeNow,
		LastLogin:             timeNow,
	}
	mockRepositoryInstance.On("UpsertUser", mock.Anything).Return(&mockUser, nil).Once()
	mockSession := repository.Session{
		ID:                    "testsessionid",
		UserID:                "testuserid",
		RefreshTokenHash:      []byte("testrefreshtoken"),
		RefreshTokenExpiresAt: timeNow,
		CreatedAt:             timeNow,
		UpdatedAt:             timeNow,
		RevokedAt:             &timeNow,
	}
	mockRepositoryInstance.On("CreateSession", mock.Anything).Return(&mockSession, nil).Once()

	mockJwtInstance := &mockJwt{}
	mockJwtInstance.On("GenerateJwt", mock.Anything).Return("", fmt.Errorf("error")).Once()

	_, err := NewAuthService(mockRepositoryInstance, mockJwtInstance,
		mockAesInstance).Login(loginInput)

	mock.AssertExpectationsForObjects(t, mockAesInstance, mockRepositoryInstance, mockJwtInstance)
	assert.NotEqual(t, err, nil)
}

func Test_RefreshSuccess(t *testing.T) {
	refreshToken := "testrefreshtoken"
	hashedToken := hashString(refreshToken)

	mockRepositoryInstance := &mockRepository{}
	timeNow := time.Now()
	mockSession := repository.Session{
		ID:                    "testsessionid",
		UserID:                "testuserid",
		RefreshTokenHash:      []byte(hashedToken),
		RefreshTokenExpiresAt: timeNow.Add(time.Hour),
		CreatedAt:             timeNow,
		UpdatedAt:             timeNow,
		RevokedAt:             nil,
	}
	mockRepositoryInstance.On("GetSessionForTokenHash", mock.Anything).Return(&mockSession, nil).Once()
	mockRepositoryInstance.On("UpdateSession", mock.Anything).Return(nil).Once()

	mockJwtInstance := &mockJwt{}
	mockJwtAccessToken := "testjwtaccesstoken"
	mockJwtInstance.On("GenerateJwt", mock.Anything).Return(mockJwtAccessToken, nil).Once()

	actualResponse, err := NewAuthService(mockRepositoryInstance, mockJwtInstance,
		nil).Refresh(refreshToken)

	mock.AssertExpectationsForObjects(t, mockRepositoryInstance, mockJwtInstance)
	assert.Equal(t, err, nil)
	assert.Equal(t, actualResponse.AccessToken, mockJwtAccessToken)
	assert.NotEqual(t, actualResponse.RefreshToken, refreshToken)
}

func Test_RefreshSessionDoesNotExist(t *testing.T) {
	refreshToken := "testrefreshtoken"

	mockRepositoryInstance := &mockRepository{}
	mockRepositoryInstance.On("GetSessionForTokenHash", mock.Anything).Return(
		&repository.Session{}, fmt.Errorf("error")).Once()

	_, err := NewAuthService(mockRepositoryInstance, nil,
		nil).Refresh(refreshToken)

	mock.AssertExpectationsForObjects(t, mockRepositoryInstance)
	assert.NotEqual(t, err, nil)
}

func Test_RefreshSessionRevoked(t *testing.T) {
	refreshToken := "testrefreshtoken"
	hashedToken := hashString(refreshToken)

	mockRepositoryInstance := &mockRepository{}
	timeNow := time.Now()
	sessionRevokedTime := time.Now().Add(-1 * time.Hour)
	mockSession := repository.Session{
		ID:                    "testsessionid",
		UserID:                "testuserid",
		RefreshTokenHash:      []byte(hashedToken),
		RefreshTokenExpiresAt: timeNow.Add(time.Hour),
		CreatedAt:             timeNow,
		UpdatedAt:             timeNow,
		RevokedAt:             &sessionRevokedTime,
	}
	mockRepositoryInstance.On("GetSessionForTokenHash", mock.Anything).Return(&mockSession, nil).Once()

	_, err := NewAuthService(mockRepositoryInstance, nil,
		nil).Refresh(refreshToken)

	mock.AssertExpectationsForObjects(t, mockRepositoryInstance)
	assert.NotEqual(t, err, nil)
}

func Test_RefreshSessionExpired(t *testing.T) {
	refreshToken := "testrefreshtoken"
	hashedToken := hashString(refreshToken)

	mockRepositoryInstance := &mockRepository{}
	timeNow := time.Now()
	mockSession := repository.Session{
		ID:                    "testsessionid",
		UserID:                "testuserid",
		RefreshTokenHash:      []byte(hashedToken),
		RefreshTokenExpiresAt: timeNow.Add(-1 * time.Hour),
		CreatedAt:             timeNow,
		UpdatedAt:             timeNow,
		RevokedAt:             nil,
	}
	mockRepositoryInstance.On("GetSessionForTokenHash", mock.Anything).Return(&mockSession, nil).Once()

	_, err := NewAuthService(mockRepositoryInstance, nil,
		nil).Refresh(refreshToken)

	mock.AssertExpectationsForObjects(t, mockRepositoryInstance)
	assert.NotEqual(t, err, nil)
}

func Test_RefreshUpdateSessionError(t *testing.T) {
	refreshToken := "testrefreshtoken"
	hashedToken := hashString(refreshToken)

	mockRepositoryInstance := &mockRepository{}
	timeNow := time.Now()
	mockSession := repository.Session{
		ID:                    "testsessionid",
		UserID:                "testuserid",
		RefreshTokenHash:      []byte(hashedToken),
		RefreshTokenExpiresAt: timeNow.Add(time.Hour),
		CreatedAt:             timeNow,
		UpdatedAt:             timeNow,
		RevokedAt:             nil,
	}
	mockRepositoryInstance.On("GetSessionForTokenHash", mock.Anything).Return(&mockSession, nil).Once()
	mockRepositoryInstance.On("UpdateSession", mock.Anything).Return(fmt.Errorf("error")).Once()

	_, err := NewAuthService(mockRepositoryInstance, nil,
		nil).Refresh(refreshToken)

	mock.AssertExpectationsForObjects(t, mockRepositoryInstance)
	assert.NotEqual(t, err, nil)
}

func Test_RefreshJwtError(t *testing.T) {
	refreshToken := "testrefreshtoken"
	hashedToken := hashString(refreshToken)

	mockRepositoryInstance := &mockRepository{}
	timeNow := time.Now()
	mockSession := repository.Session{
		ID:                    "testsessionid",
		UserID:                "testuserid",
		RefreshTokenHash:      []byte(hashedToken),
		RefreshTokenExpiresAt: timeNow.Add(time.Hour),
		CreatedAt:             timeNow,
		UpdatedAt:             timeNow,
		RevokedAt:             nil,
	}
	mockRepositoryInstance.On("GetSessionForTokenHash", mock.Anything).Return(&mockSession, nil).Once()
	mockRepositoryInstance.On("UpdateSession", mock.Anything).Return(nil).Once()

	mockJwtInstance := &mockJwt{}
	mockJwtInstance.On("GenerateJwt", mock.Anything).Return("", fmt.Errorf("error")).Once()

	_, err := NewAuthService(mockRepositoryInstance, mockJwtInstance,
		nil).Refresh(refreshToken)

	mock.AssertExpectationsForObjects(t, mockRepositoryInstance, mockJwtInstance)
	assert.NotEqual(t, err, nil)
}
