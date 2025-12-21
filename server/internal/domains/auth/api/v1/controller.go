package v1

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/TBuckholz5/bookshelf/internal/domains/auth/models"
	"github.com/TBuckholz5/bookshelf/internal/domains/auth/service"
	"github.com/go-playground/validator/v10"
	"golang.org/x/oauth2"
)

type Controller interface {
	GoogleLogin(w http.ResponseWriter, r *http.Request)
	GoogleCallback(w http.ResponseWriter, r *http.Request)
}

type AuthController struct {
	service           *service.AuthService
	validate          *validator.Validate
	googleOAuthConfig oauth2.Config
}

func NewAuthController(service *service.AuthService, validate *validator.Validate, googleOAuthConfig oauth2.Config) *AuthController {
	return &AuthController{service: service, validate: validate, googleOAuthConfig: googleOAuthConfig}
}

func (c *AuthController) GoogleLogin(w http.ResponseWriter, r *http.Request) {
	url := c.googleOAuthConfig.AuthCodeURL("randomstate")
	http.Redirect(w, r, url, http.StatusSeeOther)
}

func (c *AuthController) GoogleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	if state != "randomstate" {
		http.Error(w, "States don't Match!", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")

	token, err := c.googleOAuthConfig.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, "Code-Token Exchange Failed", http.StatusInternalServerError)
		return
	}

	resp, err := http.Get(
		"https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken,
	)
	if err != nil {
		http.Error(w, "User Data Fetch Failed", http.StatusInternalServerError)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	userData, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "JSON Parsing Failed", http.StatusInternalServerError)
		return
	}

	var userInfo models.OAuthUserInfo
	if err := json.Unmarshal(userData, &userInfo); err != nil {
		http.Error(w, "Error unmarshaling user info", http.StatusInternalServerError)
		return
	}

	jwtToken, err := c.service.Login(&models.UserLoginRequestInfo{
		OAuthType:        models.Google,
		ExternalUserInfo: &userInfo,
		Token:            token,
	})
	if err != nil {
		http.Error(w, "Service Error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(models.UserLoginResponse{Token: jwtToken}); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}
