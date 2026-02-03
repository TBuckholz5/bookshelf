package repository

import "time"

type User struct {
	ID                    string
	Email                 string
	DisplayName           string
	OAuthProviderID       string
	OAuthProviderName     string
	EncryptedAccessToken  []byte
	EncryptedRefreshToken []byte
	CreatedAt             time.Time
	UpdatedAt             time.Time
	LastLogin             time.Time
}

type Session struct {
	ID                    string
	UserID                string
	RefreshTokenHash      []byte
	RefreshTokenExpiresAt time.Time
	CreatedAt             time.Time
	UpdatedAt             time.Time
	RevokedAt             *time.Time
}
