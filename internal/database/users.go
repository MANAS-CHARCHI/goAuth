package database

import (
	"database/sql"
	"fmt"
	"time"
)

type UserModel struct {
	DB *sql.DB
}

type RegisterRequest struct {
	Username  string `json:"username"`
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type UserResponse struct {
	Id        int    `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	FirstName string `json:"firstName,omitempty"`
	LastName  string `json:"lastName,omitempty"`
	Avatar    string `json:"avatar,omitempty"`
	Website   string `json:"website,omitempty"`
	CreatedAt string `json:"createdAt"`
}

type UserDB struct {
	Id                  int
	Username            string
	Email               string
	Password            string
	LastPassword        *string
	PasswordChangedAt   *string
	LastPasswordResetAt *string
	FailedLoginAttempts int
	RoleId              int
	ActivationToken     *string
	PasswordResetToken  *string
	SignUpIP            *string
	LastLoginIP         *string
	UserAgent           *string
	UserUpdatedBy       *int
	FirstName           *string
	LastName            *string
	Avatar              *string
	Dob                 *string
	Gender              *string
	PhoneNumberOne      *string
	PhoneNumberTwo      *string
	Address             *string
	UserActivate        bool
	UserActivatedAt     *string
	Website             *string
	CreatedAt           string
	LastLogin           string
	LastModified        string
	IsDeleted           bool
	DeletedAt           *string
	DeletedBy           *int
}

func (m *UserModel) CreateUser(user *RegisterRequest, userAgent string) (*UserResponse, error) {

	createdAt:=time.Now().UTC().Format(time.RFC3339)
	LastLogin:=createdAt
	LastModified:=createdAt
	RoleId:=1
	query:=`INSERT INTO users (username, email, password, firstname, lastname, createdAt, roleId, lastLogin, lastModified, userAgent)
		VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id, username, email, firstname, lastname, avatar, website, createdAt;`
	
	row:=m.DB.QueryRow(query, user.Username, user.Email, user.Password, user.FirstName, user.LastName, createdAt, RoleId, LastLogin, LastModified, userAgent)
	var resp UserResponse
	var avatar sql.NullString
	var website sql.NullString
	err:=row.Scan(&resp.Id, &resp.Username, &resp.Email, &resp.FirstName, &resp.LastName, &avatar, &website, &resp.CreatedAt)
	if err!=nil{
		fmt.Println(err)
		return nil, err
	}
	resp.Avatar = avatar.String
	resp.Website = website.String

	return &resp, nil
}