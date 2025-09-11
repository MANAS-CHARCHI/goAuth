package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/httprate"
	"github.com/joho/godotenv"

	"goauth/internal/api"
	"goauth/internal/db"
)

func main() {
	_ = godotenv.Load()
	dsn := db.DSNFromEnv()
	pool := db.MustConnect(dsn)
	defer pool.Close()

	r := chi.NewRouter()

	// Basic rate limits: 100 req/min by IP
	r.Use(httprate.LimitByIP(100, 1*time.Minute))

	api.RegisterRoutes(r, pool)

	srv := &http.Server{
		Addr:         ":" + getenv("PORT", "8443"),
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
		TLSConfig:    &tls.Config{MinVersion: tls.VersionTLS12},
	}

	cert := os.Getenv("TLS_CERT_PATH")
	key := os.Getenv("TLS_KEY_PATH")

	log.Printf("authsvc listening on %s (HTTP)", srv.Addr)

	if err := srv.ListenAndServeTLS(cert, key); err != nil {
		log.Fatal(err)
	}
}

func getenv(k, def string) string {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	return v
}
