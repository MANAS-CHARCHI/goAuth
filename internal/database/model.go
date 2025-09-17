package database

import "database/sql"

type Models struct {
	DB    *sql.DB
	Users UserModel
}

func NewModels(db *sql.DB) Models {
	return Models{
		DB:    db,
		Users: UserModel{DB: db},
	}
}
