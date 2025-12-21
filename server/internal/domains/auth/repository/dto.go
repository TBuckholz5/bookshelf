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
	UserID    string
	ExpiresAt time.Time
}
