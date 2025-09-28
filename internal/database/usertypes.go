package database

import (
	"github.com/google/uuid"
)

type RegisterRequest struct {
	Username  string `json:"username"`
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"firstname"`
	LastName  string `json:"lastname"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type UserResponse struct {
	// Id            uuid.UUID `json:"id"`
	Username      string    `json:"username"`
	Email         string    `json:"email"`
	FirstName     string    `json:"firstName "`
	LastName      string    `json:"lastName "`
	Avatar        string    `json:"avatar "`
	Website       string    `json:"website "`
	CreatedAt     string    `json:"createdAt"`
	UserActivated bool      `json:"userActivated"`
}

type UserInfo struct {
	Username        string `json:"username"`
	Email           string `json:"email"`
	FirstName       string `json:"firstName "`
	LastName        string `json:"lastName "`
	Avatar          string `json:"avatar "`
	Website         string `json:"website "`
	Role            string `json:"role"`
	Gender          string `json:"gender "`
	Dob             string `json:"dob "`
	PhoneOne        string `json:"phoneNumberOne "`
	PhoneTwo        string `json:"phoneNumberTwo "`
	Address         string `json:"address"`
	CreatedAt       string `json:"createdAt"`
	LastLogin       string `json:"lastLogin"`
	LastModified    string `json:"lastModified"`
	UserActivatedAt string `json:"userActivatedAt"`
}

type UpdateUser struct {
	Username  string `json:"username"`
	FirstName string `json:"firstname"`
	LastName  string `json:"lastName"`
	Avatar    string `json:"avatar"`
	Website   string `json:"website"`
	Gender    string `json:"gender"`
	Dob       string `json:"dob"`
	PhoneOne  string `json:"phoneNumberOne"`
	PhoneTwo  string `json:"phoneNumberTwo"`
	Address   string `json:"address"`
}

type UserDB struct {
	Id                   uuid.UUID
	Username             string
	Email                string
	Password             string
	LastPassword         *string
	PasswordChangedAt    *string
	LastPasswordResetAt  *string
	FailedLoginAttempts  int
	RoleId               int
	ActivationToken      *string
	PasswordResetToken   *string
	SignUpIP             *string
	LastLoginIP          *string
	UserAgent            *string
	FailedLoginUserAgent *string
	UserUpdatedBy        *int
	FirstName            *string
	LastName             *string
	Avatar               *string
	Dob                  *string
	Gender               *string
	PhoneNumberOne       *string
	PhoneNumberTwo       *string
	Address              *string
	UserActivate         bool
	UserActivatedAt      *string
	Website              *string
	CreatedAt            string
	LastLogin            string
	LastModified         string
	IsDeleted            bool
	DeletedAt            *string
	DeletedBy            *int
}

type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}

type UpdateUserRequest struct {
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Username  string `json:"username"`
	Avatar    string `json:"avatar"`
	Website   string `json:"website"`
	Gender    string `json:"gender"`
	Dob       string `json:"dob"`
	PhoneOne  string `json:"phonenumberone"`
	PhoneTwo  string `json:"phonenumbertwo"`
	Address   string `json:"address"`
}