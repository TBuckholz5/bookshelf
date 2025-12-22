package service

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"time"

	"github.com/TBuckholz5/bookshelf/internal/domains/auth/models"
	"github.com/TBuckholz5/bookshelf/internal/domains/auth/repository"
	"github.com/TBuckholz5/bookshelf/internal/util/aes"
	"github.com/TBuckholz5/bookshelf/internal/util/jwt"
)

const (
	SESSION_EXPIRATION         = time.Duration(15 * time.Minute)
	SESSION_REFRESH_EXPIRATION = time.Duration(7 * 24 * time.Hour)
)

type Service interface {
	Login(req models.UserLoginRequestInfo) (models.UserLoginResponse, error)
	Refresh(refreshToken string) (models.UserLoginResponse, error)
}

type AuthService struct {
	repository repository.Repository
	jwtService jwt.JwtService
	aesService aes.AesService
}

func NewAuthService(repository repository.Repository, jwtService jwt.JwtService, aesService aes.AesService) *AuthService {
	return &AuthService{repository: repository, jwtService: jwtService, aesService: aesService}
}

// Logs in the user, creating/updating the user table, creating a session, and issuing a JWT.
func (s *AuthService) Login(req models.UserLoginRequestInfo) (models.UserLoginResponse, error) {
	// Encrypt oauth tokens via AES.
	encryptedAccessToken, err := s.aesService.Encrypt([]byte(req.Token.AccessToken))
	if err != nil {
		return models.UserLoginResponse{}, err
	}
	encryptedRefreshToken, err := s.aesService.Encrypt([]byte(req.Token.RefreshToken))
	if err != nil {
		return models.UserLoginResponse{}, err
	}
	// Store user row.
	repoUser, err := s.repository.UpsertUser(&repository.UpsertUserRequest{
		OAuthType:             req.OAuthType,
		ExternalUserInfo:      *req.ExternalUserInfo,
		EncryptedAccessToken:  encryptedAccessToken,
		EncryptedRefreshToken: encryptedRefreshToken,
	})
	if err != nil {
		return models.UserLoginResponse{}, err
	}

	// Generate refresh token randomly, base64 encode it, then hash the result.
	refreshToken, err := generateRefreshToken()
	if err != nil {
		return models.UserLoginResponse{}, err
	}

	// Store the session row.
	sessionRefreshExpiration := time.Now().Add(SESSION_REFRESH_EXPIRATION)
	session, err := s.repository.CreateSession(&repository.CreateSessionRequest{
		UserID:                repoUser.ID,
		RefreshTokenHash:      hashString(refreshToken),
		RefreshTokenExpiresAt: sessionRefreshExpiration,
	})
	if err != nil {
		return models.UserLoginResponse{}, err
	}

	// Return JWT.
	accessToken, err := s.jwtService.GenerateJwt(jwt.JwtClaims{
		SessionID: session.ID,
		UserID:    repoUser.ID,
		Expiry:    time.Now().Add(SESSION_EXPIRATION),
	})
	if err != nil {
		return models.UserLoginResponse{}, err
	}
	return models.UserLoginResponse{
		AccessToken: accessToken, RefreshToken: refreshToken,
	}, nil
}

// Refreshes the user's JWT and OAuth token.
func (s *AuthService) Refresh(refreshToken string) (models.UserLoginResponse, error) {
	// Validate session.
	refreshTokenHash := hashString(refreshToken)
	session, err := s.repository.GetSessionForTokenHash(refreshTokenHash)
	if err != nil {
		return models.UserLoginResponse{}, NewUnauthorizedError("session not found")
	}
	if session.RevokedAt != nil && time.Now().After(*session.RevokedAt) {
		return models.UserLoginResponse{}, NewUnauthorizedError("session has been revoked")
	}
	if time.Now().After(session.RefreshTokenExpiresAt) {
		return models.UserLoginResponse{}, NewUnauthorizedError("session refresh token has expired")
	}

	// Generate new refresh token randomly, base64 encode it, then hash the result.
	newRefreshToken, err := generateRefreshToken()
	if err != nil {
		return models.UserLoginResponse{}, err
	}

	// Store the session row.
	sessionRefreshExpiration := time.Now().Add(SESSION_REFRESH_EXPIRATION)
	if err = s.repository.UpdateSession(&repository.UpdateSessionRequest{
		ID:                    session.ID,
		RefreshTokenHash:      hashString(newRefreshToken),
		RefreshTokenExpiresAt: sessionRefreshExpiration,
	}); err != nil {
		return models.UserLoginResponse{}, err
	}

	// Return JWT.
	accessToken, err := s.jwtService.GenerateJwt(jwt.JwtClaims{
		SessionID: session.ID,
		UserID:    session.UserID,
		Expiry:    time.Now().Add(SESSION_EXPIRATION),
	})
	if err != nil {
		return models.UserLoginResponse{}, NewInternalError("failed to generate jwt")
	}
	return models.UserLoginResponse{
		AccessToken: accessToken, RefreshToken: newRefreshToken,
	}, nil
}

func generateRefreshToken() (string, error) {
	refreshTokenBytes := make([]byte, 32)
	if _, err := rand.Read(refreshTokenBytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(refreshTokenBytes), nil
}

func hashString(s string) []byte {
	fixedHash := sha256.Sum256([]byte(s))
	return fixedHash[:]
}
