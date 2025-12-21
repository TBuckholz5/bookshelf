package repository

import "github.com/jackc/pgx/v5/pgxpool"

type Repository interface{}

type AuthRepository struct {
	pool *pgxpool.Pool
}

func NewAuthRepository(pool *pgxpool.Pool) *AuthRepository {
	return &AuthRepository{pool: pool}
}
