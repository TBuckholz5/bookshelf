package repository

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Repository interface {
	UpsertUser(req *UpsertUserRequest) (*User, error)
	CreateSession(req *CreateSessionRequest) (*Session, error)
	UpdateSession(req *UpdateSessionRequest) error
	GetSessionForTokenHash(tokenHash []byte) (*Session, error)
}

type AuthRepository struct {
	pool *pgxpool.Pool
}

func NewAuthRepository(pool *pgxpool.Pool) *AuthRepository {
	return &AuthRepository{pool: pool}
}

func (r *AuthRepository) UpsertUser(req *UpsertUserRequest) (*User, error) {
	query := `INSERT INTO users (oauth_provider_id, oauth_provider_name, email, display_name, encrypted_access_token,
			encrypted_refresh_token, last_login) 
		VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP) 
		ON CONFLICT (oauth_provider_name, oauth_provider_id) 
		DO UPDATE SET 
			encrypted_access_token = $5,
			encrypted_refresh_token = $6,
			updated_at = CURRENT_TIMESTAMP,
			last_login = CURRENT_TIMESTAMP 
		RETURNING id, oauth_provider_id, oauth_provider_name, email, display_name, encrypted_access_token,
		encrypted_refresh_token, created_at, updated_at, last_login;`
	row := r.pool.QueryRow(context.Background(), query, req.ExternalUserInfo.ID, req.OAuthType,
		req.ExternalUserInfo.Email, req.ExternalUserInfo.Name, req.EncryptedAccessToken, req.EncryptedRefreshToken)
	var user User
	err := row.Scan(&user.ID, &user.OAuthProviderID, &user.OAuthProviderName, &user.Email, &user.DisplayName,
		&user.EncryptedAccessToken, &user.EncryptedRefreshToken, &user.CreatedAt, &user.UpdatedAt, &user.LastLogin)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *AuthRepository) CreateSession(req *CreateSessionRequest) (*Session, error) {
	query := `INSERT INTO sessions (user_id, refresh_token_hash, refresh_token_expire_at) 
		VALUES ($1, $2, $3) 
		RETURNING id, user_id, refresh_token_hash, refresh_token_expire_at, 
		created_at, updated_at, revoked_at;`
	row := r.pool.QueryRow(context.Background(), query, req.UserID,
		req.RefreshTokenHash, req.RefreshTokenExpiresAt)
	var session Session
	err := row.Scan(&session.ID, &session.UserID, &session.RefreshTokenHash,
		&session.RefreshTokenExpiresAt, &session.CreatedAt, &session.UpdatedAt, &session.RevokedAt)
	if err != nil {
		return nil, err
	}
	return &session, nil
}

func (r *AuthRepository) UpdateSession(req *UpdateSessionRequest) error {
	query := `UPDATE sessions SET refresh_token_hash = $1, refresh_token_expire_at = $2 
			WHERE id = $3`
	_, err := r.pool.Exec(context.Background(), query, req.RefreshTokenHash, req.RefreshTokenExpiresAt,
		req.ID)
	return err
}

func (r *AuthRepository) GetSessionForTokenHash(tokenHash []byte) (*Session, error) {
	query := `SELECT id, user_id, refresh_token_hash, refresh_token_expire_at, 
		created_at, updated_at, revoked_at FROM sessions WHERE 
		refresh_token_hash = $1`
	row := r.pool.QueryRow(context.Background(), query, tokenHash)
	var session Session
	err := row.Scan(&session.ID, &session.UserID, &session.RefreshTokenHash,
		&session.RefreshTokenExpiresAt, &session.CreatedAt, &session.UpdatedAt, &session.RevokedAt)
	if err != nil {
		return nil, err
	}
	return &session, nil
}
