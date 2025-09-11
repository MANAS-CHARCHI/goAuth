package db

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type DSN struct {
	Host, Port, User, Pass, Name, SSLMode string
}

func DSNFromEnv() DSN {
	return DSN{
		Host:    os.Getenv("DB_HOST"),
		Port:    os.Getenv("DB_PORT"),
		User:    os.Getenv("DB_USER"),
		Pass:    os.Getenv("DB_PASSWORD"),
		Name:    os.Getenv("DB_NAME"),
		SSLMode: os.Getenv("DB_SSLMODE"),
	}
}

func MustConnect(d DSN) *pgxpool.Pool {
	uri := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s", d.User, d.Pass, d.Host, d.Port, d.Name, d.SSLMode)
	cfg, err := pgxpool.ParseConfig(uri)
	if err != nil {
		panic(err)
	}
	cfg.MaxConns = 10
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		panic(err)
	}
	if err := pool.Ping(ctx); err != nil {
		panic(err)
	}
	return pool
}
