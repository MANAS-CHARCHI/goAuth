package database

import (
	"database/sql"
)

type SessionModel struct {
	DB *sql.DB
}

type SessionDB struct {
	Id           int
	UserId       int
	SessionToken string
	UserAgent    string
	IpAddress    string
	CreatedAt    string
	LastActiveAt string
	IsActive     bool
	ExpiresAt    string
}
