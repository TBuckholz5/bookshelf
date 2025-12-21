package service

import (
	"github.com/TBuckholz5/bookshelf/internal/domains/auth/models"
	"github.com/TBuckholz5/bookshelf/internal/domains/auth/repository"
	"github.com/TBuckholz5/bookshelf/internal/util/aes"
	"github.com/TBuckholz5/bookshelf/internal/util/jwt"
)

type Service interface {
	Login(req models.UserLoginRequestInfo) (string, error)
}

type AuthService struct {
	repository *repository.AuthRepository
	jwtService jwt.JwtService
	aesService aes.AesService
}

func NewAuthService(repository *repository.AuthRepository, jwtService jwt.JwtService, aesService aes.AesService) *AuthService {
	return &AuthService{repository: repository, jwtService: jwtService, aesService: aesService}
}

// Login service for user auth.
// 1. Creates/updates user and session in the db.
// 2. Returns JWT for user, with same expiration as external token.
func (s *AuthService) Login(req *models.UserLoginRequestInfo) (string, error) {
	// Encrypt oauth tokens via AES.
	encryptedAccessToken, err := s.aesService.Encrypt([]byte(req.Token.AccessToken))
	if err != nil {
		return "", err
	}
	encryptedRefreshToken, err := s.aesService.Encrypt([]byte(req.Token.RefreshToken))
	if err != nil {
		return "", err
	}
	// Store user row.
	repoUser, err := s.repository.UpsertUser(&repository.UpsertUserRequest{
		OAuthType:             req.OAuthType,
		ExternalUserInfo:      *req.ExternalUserInfo,
		EncryptedAccessToken:  encryptedAccessToken,
		EncryptedRefreshToken: encryptedRefreshToken,
	})
	if err != nil {
		return "", err
	}
	// Store session row.
	err = s.repository.RevokeOldSessions(repoUser.ID)
	if err != nil {
		return "", err
	}
	_, err = s.repository.CreateSession(&repository.CreateSessionRequest{
		UserID:    repoUser.ID,
		ExpiresAt: req.Token.Expiry,
	})
	if err != nil {
		return "", err
	}
	// Return JWT.
	return s.jwtService.GenerateJwt(repoUser.ID, req.Token.Expiry)
}
