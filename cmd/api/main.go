package main

import (
	"context"
	"database/sql"
	"fmt"
	"goAuth/internal/database"
	"log"
	"os"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"
)

type application struct {
	port      string
	jwtsecret string
	models    database.Models
	redis     *redis.Client
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}

	client := redis.NewClient(&redis.Options{
        Addr:	  os.Getenv("REDIS_SERVER"),
        Password: "", // No password set
        DB:		  0,  // Use default DB
        Protocol: 2,  // Connection protocol
    })
	// Always use a context (required by go-redis v9)
	ctx := context.Background()

	// Test the connection
	if err := client.Ping(ctx).Err(); err != nil {
		log.Fatalf("Could not connect to Redis: %v", err)
	}

	fmt.Printf("----------Started Redis on %s----------\n", os.Getenv("REDIS_SERVER"))

	dbUrl := os.Getenv("DATABASE_URL")
	if dbUrl == "" {
		log.Fatal("DATABASE_URL is not set")
	}

	db, err := sql.Open("postgres", dbUrl)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatal("Failed to ping DB:", err)
	}
	fmt.Println("----------Started Postgres on localhost:5432----------")

	port := os.Getenv("PORT")
	if port == "" {
		port = "5003"
	}

	app := &application{
		port:      port,
		jwtsecret: os.Getenv("JWT_SECRET"),
		models:    database.NewModels(db, client),
		redis:     client,
	}
	fmt.Printf("----------Started Server on http://localhost:%s----------\n", port)
	if err := app.serve(); err != nil {
		log.Fatal(err)
	}

}
