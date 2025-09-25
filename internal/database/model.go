package database

import (
	"database/sql"

	"github.com/redis/go-redis/v9"
)

type Models struct {
	DB    *sql.DB
	Users UserModel
	Redis *redis.Client
}

func NewModels(db *sql.DB, redisClient *redis.Client) Models {
	return Models{
		DB:    db,
		Users: UserModel{DB: db, Redis: redisClient},
	}
}
