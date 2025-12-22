package models

import (
	"golang.org/x/oauth2"
)

const (
	Google string = "Google"
)

type OAuthUserInfo struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

type UserLoginRequestInfo struct {
	OAuthType        string
	ExternalUserInfo *OAuthUserInfo
	Token            *oauth2.Token
}

type UserLoginResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

type UserRefreshRequest struct {
	RefreshToken string `json:"refreshToken"`
}
