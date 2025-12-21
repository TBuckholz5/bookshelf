package config

import (
	"os"

	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type Config struct {
	ServerPort        string
	ServerHost        string
	JWTSecret         string
	DBUser            string
	DBPort            string
	DBName            string
	DBHost            string
	DBPassword        string
	SslMode           string
	GoogleLoginConfig oauth2.Config
}

func LoadConfig() (*Config, error) {
	err := godotenv.Load()
	if err != nil {
		return nil, err
	}

	serverPort := os.Getenv("SERVER_PORT")
	serverHost := os.Getenv("SERVER_HOST")
	jwtSecret := os.Getenv("JWT_SECRET")

	databasePort := os.Getenv("DATABASE_PORT")
	databaseUser := os.Getenv("DATABASE_USER")
	databaseName := os.Getenv("DATABASE_NAME")
	databaseHost := os.Getenv("DATABASE_HOST")
	databasePassword := os.Getenv("DATABASE_PASSWORD")
	databaseSslMode := os.Getenv("DATABASE_SSLMODE")

	return &Config{
		ServerPort: serverPort,
		ServerHost: serverHost,
		JWTSecret:  jwtSecret,
		DBUser:     databaseUser,
		DBPort:     databasePort,
		DBName:     databaseName,
		DBHost:     databaseHost,
		DBPassword: databasePassword,
		SslMode:    databaseSslMode,
		GoogleLoginConfig: oauth2.Config{
			RedirectURL:  "http://localhost:8081/api/v1/auth/google_callback",
			ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
			ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
			Scopes: []string{
				"https://www.googleapis.com/auth/userinfo.email",
				"https://www.googleapis.com/auth/userinfo.profile",
			},
			Endpoint: google.Endpoint,
		},
	}, nil
}
