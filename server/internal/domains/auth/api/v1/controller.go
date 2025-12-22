package v1

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/TBuckholz5/bookshelf/internal/domains/auth/models"
	"github.com/TBuckholz5/bookshelf/internal/domains/auth/service"
	"golang.org/x/oauth2"
)

type GoogleOAuth interface {
	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string
	Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error)
}

type HttpClient interface {
	Get(url string) (resp *http.Response, err error)
}

type Controller interface {
	GoogleLogin(w http.ResponseWriter, r *http.Request)
	GoogleCallback(w http.ResponseWriter, r *http.Request)
	RefreshSession(w http.ResponseWriter, r *http.Request)
}

type AuthController struct {
	service           service.Service
	googleOAuthConfig GoogleOAuth
	httpClient        HttpClient
}

const oAuthState = "bookshelfstate"

func NewAuthController(service service.Service,
	googleOAuthConfig GoogleOAuth, httpClient HttpClient,
) *AuthController {
	return &AuthController{service: service, googleOAuthConfig: googleOAuthConfig, httpClient: httpClient}
}

func (c *AuthController) GoogleLogin(w http.ResponseWriter, r *http.Request) {
	url := c.googleOAuthConfig.AuthCodeURL(oAuthState)
	http.Redirect(w, r, url, http.StatusSeeOther)
}

func (c *AuthController) GoogleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	if state != oAuthState {
		http.Error(w, "States don't Match!", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")

	token, err := c.googleOAuthConfig.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, "Code-Token Exchange Failed", http.StatusInternalServerError)
		return
	}

	resp, err := c.httpClient.Get(
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

	response, err := c.service.Login(models.UserLoginRequestInfo{
		OAuthType:        models.Google,
		ExternalUserInfo: &userInfo,
		Token:            token,
	})
	if err != nil {
		http.Error(w, "Service Error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (c *AuthController) RefreshSession(w http.ResponseWriter, r *http.Request) {
	// Parse body for refreshToken.
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "could not parse request body", http.StatusInternalServerError)
		return
	}
	defer func() { _ = r.Body.Close() }()

	var request models.UserRefreshRequest
	if err := json.Unmarshal(bodyBytes, &request); err != nil {
		http.Error(w, "could not unmarshal body json", http.StatusInternalServerError)
		return
	}

	response, err := c.service.Refresh(request.RefreshToken)
	var unauthError *service.UnauthorizedError
	var internalError *service.InternalError
	if errors.As(err, &unauthError) {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	} else if errors.As(err, &internalError) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err != nil {
		http.Error(w, "Service Error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}
