package jwt

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const ISSUER = "bookshelf"

type JwtClaims struct {
	SessionID string
	UserID    string
	Expiry    time.Time
	Issuer    string
}

type JwtService interface {
	GenerateJwt(claims JwtClaims) (string, error)
	ValidateJwt(tokenString string) (JwtClaims, error)
}

type Jwt struct {
	secret []byte
}

func NewJwtService(jwtSecret []byte) *Jwt {
	return &Jwt{
		secret: jwtSecret,
	}
}

func (j *Jwt) GenerateJwt(claims JwtClaims) (string, error) {
	jwtClaims := jwt.MapClaims{
		"exp":      claims.Expiry.Unix(),
		"sub":      claims.UserID,
		"iss":      ISSUER,
		"sid":      claims.SessionID,
		"issuedAt": time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtClaims)

	signedToken, err := token.SignedString(j.secret)
	if err != nil {
		return "", err
	}
	return signedToken, nil
}

func (j *Jwt) ValidateJwt(tokenString string) (JwtClaims, error) {
	claims, err := parseToken(j.secret, tokenString)
	if err != nil {
		return JwtClaims{}, err
	}
	if claims.Issuer != ISSUER {
		return JwtClaims{}, fmt.Errorf("invalid token issuer")
	}
	if time.Now().After(claims.Expiry) {
		return JwtClaims{}, fmt.Errorf("token has expired")
	}
	return claims, nil
}

func parseToken(secret []byte, tokenString string) (JwtClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		return secret, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil {
		return JwtClaims{}, fmt.Errorf("could not parse jwt")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return JwtClaims{}, fmt.Errorf("invalid token claims")
	}
	sub, ok := claims["sub"].(string)
	if !ok {
		return JwtClaims{}, fmt.Errorf("sub not a string")
	}
	sid, ok := claims["sid"].(string)
	if !ok {
		return JwtClaims{}, fmt.Errorf("sid not a string")
	}
	expValue, ok := claims["exp"].(float64)
	if !ok {
		return JwtClaims{}, fmt.Errorf("exp claim is missing or not a number")
	}
	issuer, ok := claims["iss"].(string)
	if !ok {
		return JwtClaims{}, fmt.Errorf("iss is not a string")
	}
	return JwtClaims{
		UserID:    sub,
		SessionID: sid,
		Expiry:    time.Unix(int64(expValue), 0),
		Issuer:    issuer,
	}, nil
}
