package database

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
	Id                   int
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
