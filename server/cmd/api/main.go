package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/TBuckholz5/bookshelf/internal/config"
	authApi "github.com/TBuckholz5/bookshelf/internal/domains/auth/api/v1"
	authRepo "github.com/TBuckholz5/bookshelf/internal/domains/auth/repository"
	authServ "github.com/TBuckholz5/bookshelf/internal/domains/auth/service"
	"github.com/TBuckholz5/bookshelf/internal/routing"
	"github.com/TBuckholz5/bookshelf/internal/routing/middleware"

	"github.com/TBuckholz5/bookshelf/internal/routing/middleware/logging"
	"github.com/TBuckholz5/bookshelf/internal/util/aes"
	"github.com/TBuckholz5/bookshelf/internal/util/jwt"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

func main() {
	// Read env config.
	config, err := config.LoadApiConfig()
	if err != nil {
		log.Fatal("Cannot load config:", err)
	}

	// Connect to database.
	pool, err := pgxpool.New(context.Background(), fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
		config.DBUser, config.DBPassword, config.DBHost, config.DBPort, config.DBName, config.SslMode))
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()

	// Run migration.
	db := stdlib.OpenDBFromPool(pool)
	defer func() { _ = db.Close() }()
	if err := goose.Up(db, "migrations"); err != nil {
		log.Fatal(err)
	}

	// Define dependencies.
	jwtService := jwt.NewJwtService([]byte(config.JWTSecret))
	aesService := aes.NewAesService([]byte(config.AESSecret))
	loggingMiddleware := logging.NewLoggingMiddleware()

	authRepository := authRepo.NewAuthRepository(pool)
	authService := authServ.NewAuthService(authRepository, jwtService, aesService)
	authController := authApi.NewAuthController(authService,
		&config.GoogleLoginConfig, http.DefaultClient)
	// authMiddleware := auth.NewAuthMiddleware(jwtService, authRepository)

	// Register routes.
	mux := http.NewServeMux()

	apiMux := routing.RegisterRouterGroup(routing.Config{
		Mux:        mux,
		GroupRoute: "/api/v1/",
	})

	authMux := routing.RegisterRouterGroup(routing.Config{
		Mux:         apiMux,
		Middlewares: []middleware.Middleware{loggingMiddleware},
		GroupRoute:  "/auth/",
	})
	routing.RegisterRoute(routing.Config{
		Mux:     authMux,
		Handler: http.HandlerFunc(authController.GoogleLogin),
		Route:   "/google_login",
		Method:  "POST",
	})
	routing.RegisterRoute(routing.Config{
		Mux:     authMux,
		Handler: http.HandlerFunc(authController.GoogleCallback),
		Route:   "/google_callback",
		Method:  "GET",
	})
	routing.RegisterRoute(routing.Config{
		Mux:     authMux,
		Handler: http.HandlerFunc(authController.RefreshSession),
		Route:   "/refresh",
		Method:  "POST",
	})

	// Start server.
	fmt.Println("Starting server on port", config.ServerPort)
	if err := http.ListenAndServe(fmt.Sprintf(":%s", config.ServerPort), mux); err != nil {
		log.Fatal(err)
	}
}
