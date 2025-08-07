package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"onePercent/config"
	"onePercent/internal/handler"
	"onePercent/internal/repository"
	"onePercent/internal/security"
	"onePercent/internal/service"
	"onePercent/pkg/database"
	"onePercent/pkg/redis"
	"onePercent/pkg/utils"
	router "onePercent/routes"

	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	redisClient "github.com/redis/go-redis/v9"
)

type App struct {
	config *config.Config
	router *router.Router
	server *http.Server

	db          *sql.DB
	redisClient *redisClient.Client
}

func main() {
	app, err := initializeApp()
	if err != nil {
		log.Fatal("Failed to initialize app:", err)
	}
	defer app.cleanup()

	if err := app.start(); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

func initializeApp() (*App, error) {
	cfg := config.Load()
	log.Printf("Loaded configuration for environment: %s", cfg.Environment)

	// Database connection
	db, err := database.NewPostgresConnection(cfg.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("database connection failed: %w", err)
	}
	log.Println("Connected to PostgreSQL database")

	// Run migrations
	if err := database.RunMigrations(cfg.DatabaseURL); err != nil {
		db.Close()
		return nil, fmt.Errorf("migration failed: %w", err)
	}
	log.Println("Database migrations completed")

	// Redis connection
	redisClient, err := redis.NewRedisClient(cfg.RedisURL)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("redis connection failed: %w", err)
	}
	log.Println("Connected to Redis")

	// Initialize security components
	rateLimiter := security.NewRateLimiter(security.RateLimiterConfig{
		Redis:              redisClient,
		Limit:              cfg.RateLimitPerMinute,
		Interval:           cfg.RateLimitInterval,
		SkipSuccessfulAuth: false,
	})

	csrfProtection := security.NewCSRFProtection(security.CSRFConfig{
		Key:            cfg.CSRFKey,
		CookieSecure:   cfg.CookieSecure,
		CookiePath:     "/",
		CookieDomain:   "",
		CookieMaxAge:   86400, // 24 hours
		CookieSameSite: http.SameSiteStrictMode,
	})
	log.Println("Security components initialized")

	validator := utils.NewSkillValidator()

	// Initialize repositories
	userRepo := repository.NewUserRepository(db)
	refreshTokenRepo := repository.NewRefreshTokenRepository(redisClient)
	skillRepo := repository.NewSkillRepository(db)

	// Initialize services
	oauthService := service.NewOAuthService(cfg)
	authService := service.NewAuthService(cfg, userRepo, refreshTokenRepo)
	skillService := service.NewSkillService(skillRepo, validator)

	// Initialize handlers
	authHandler := handler.NewAuthHandler(oauthService, authService, userRepo, cfg)
	userHandler := handler.NewUserHandler(userRepo)
	skillHanlder := handler.NewSkillHandler(skillService)

	// Initialize router
	appRouter := router.NewRouter(authHandler, userHandler, skillHanlder, cfg, rateLimiter, csrfProtection)

	return &App{
		config:      cfg,
		router:      appRouter,
		db:          db,
		redisClient: redisClient,
	}, nil
}

func (app *App) start() error {
	// Setup routes
	handler := app.router.SetupRoutes()

	// Create HTTP server
	app.server = &http.Server{
		Addr:         ":" + app.config.Port,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Printf("Starting server on port %s...", app.config.Port)
		if err := app.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Server startup failed: %s", err)
		}
	}()

	// Log startup information
	log.Printf("🚀 Server successfully started")
	log.Printf("   Environment: %s", app.config.Environment)
	log.Printf("   Port: %s", app.config.Port)
	log.Printf("   Rate Limit: %d requests per %v", app.config.RateLimitPerMinute, app.config.RateLimitInterval)
	log.Printf("   CSRF Protection: enabled (secure cookies: %v)", app.config.CookieSecure)
	log.Printf("   JWT Token TTL: Access=%v, Refresh=%v", app.config.AccessTokenTTL, app.config.RefreshTokenTTL)

	return app.waitForShutdown()
}

func (app *App) waitForShutdown() error {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	sig := <-quit
	log.Printf("Received signal: %v. Shutting down server...", sig)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := app.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("server forced to shutdown: %w", err)
	}

	log.Println("✅ Server gracefully stopped")
	return nil
}

func (app *App) cleanup() {
	log.Println("Cleaning up resources...")

	if app.db != nil {
		app.db.Close()
		log.Println("Database connection closed")
	}

	if app.redisClient != nil {
		app.redisClient.Close()
		log.Println("Redis connection closed")
	}
}
