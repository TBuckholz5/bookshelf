package jwt

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const ISSUER = "bookshelf"

type JwtService interface {
	GenerateJwt(userID string, exp time.Time) (string, error)
	ValidateJwt(tokenString string) (string, error)
}

type Jwt struct {
	secret []byte
}

func NewJwtService(jwtSecret []byte) *Jwt {
	return &Jwt{
		secret: jwtSecret,
	}
}

func (j *Jwt) GenerateJwt(userID string, exp time.Time) (string, error) {
	claims := jwt.MapClaims{
		"exp": exp.Unix(),
		"sub": userID,
		"iss": ISSUER,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedToken, err := token.SignedString(j.secret)
	if err != nil {
		return "", err
	}
	return signedToken, nil
}

func (j *Jwt) ValidateJwt(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		return j.secret, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil {
		return "", err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return "", fmt.Errorf("invalid token claims")
	}
	if claims["iss"] != ISSUER {
		return "", fmt.Errorf("invalid token issuer")
	}
	expValue, ok := claims["exp"].(float64)
	if !ok {
		return "", fmt.Errorf("exp claim is missing or not a number")
	}
	expirationTime := time.Unix(int64(expValue), 0)
	if time.Now().After(expirationTime) {
		return "", fmt.Errorf("token has expired")
	}
	sub, ok := claims["sub"].(string)
	if !ok {
		return "", fmt.Errorf("sub not a string")
	}
	return sub, nil
}
