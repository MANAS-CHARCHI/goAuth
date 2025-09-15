package main

import (
	"database/sql"
	"goAuth/internal/database"
	"log"
	"os"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type application struct {
	port      string
	jwtsecret string
	models    database.Models
}

func main() {

	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}

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
	log.Println("Connected to DataBase.")

	port := os.Getenv("PORT")
	if port == "" {
		port = "5003"
	}

	app := &application{
		port:      port,
		jwtsecret: os.Getenv("JWT_SECRET"),
		models:    database.NewModels(db),
	}
	if err := app.serve(); err != nil {
		log.Fatal(err)
	}
	log.Printf("Starting server on http://localhost:%s", port)

}
