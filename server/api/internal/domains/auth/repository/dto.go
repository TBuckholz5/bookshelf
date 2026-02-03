package repository

import (
	"time"

	"github.com/TBuckholz5/bookshelf/internal/domains/auth/models"
)

type UpsertUserRequest struct {
	OAuthType             string
	ExternalUserInfo      models.OAuthUserInfo
	EncryptedAccessToken  []byte
	EncryptedRefreshToken []byte
}

type CreateSessionRequest struct {
	UserID                string
	RefreshTokenHash      []byte
	RefreshTokenExpiresAt time.Time
}

type UpdateSessionRequest struct {
	ID                    string
	RefreshTokenHash      []byte
	RefreshTokenExpiresAt time.Time
}
