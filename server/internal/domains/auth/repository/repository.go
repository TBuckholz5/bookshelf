package repository

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Repository interface {
	UpsertUser(req *UpsertUserRequest) (*User, error)
	CreateSession(req *CreateSessionRequest) (*Session, error)
	RevokeOldSessions(userID string) (*Session, error)
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
	query := `INSERT INTO sessions (user_id, expires_at) 
		VALUES ($1, $2) 
		RETURNING id, user_id, expires_at, created_at, updated_at, is_revoked;`
	row := r.pool.QueryRow(context.Background(), query, req.UserID, req.ExpiresAt)
	var session Session
	err := row.Scan(&session.ID, &session.UserID, &session.ExpiresAt, &session.CreatedAt, &session.UpdatedAt,
		&session.IsRevoked)
	if err != nil {
		return nil, err
	}
	return &session, nil
}

func (r *AuthRepository) RevokeOldSessions(userID string) error {
	query := `UPDATE sessions
		SET is_revoked = TRUE
		WHERE user_id = $1;`
	_, err := r.pool.Exec(context.Background(), query, userID)
	if err != nil {
		return err
	}

	return nil
}
