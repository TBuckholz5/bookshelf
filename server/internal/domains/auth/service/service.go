package service

import (
	"github.com/TBuckholz5/bookshelf/internal/domains/auth/repository"
	"github.com/TBuckholz5/bookshelf/internal/util/jwt"
)

type Service interface{}

type AuthService struct {
	repository *repository.AuthRepository
	jwtService jwt.JwtService
}

func NewAuthService(repository *repository.AuthRepository, jwtService jwt.JwtService) *AuthService {
	return &AuthService{repository: repository, jwtService: jwtService}
}
