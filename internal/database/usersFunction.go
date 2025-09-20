package database

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type UserModel struct {
	DB *sql.DB
}

var jwtSecret = []byte(os.Getenv("JWT_SECRET"))

type TokenDetails struct {
	AccessToken  string
	RefreshToken string
	AccessJTI    string
	AccessExp    int64
	RefreshExp   int64
}

// hashUserAgent hashes the User-Agent string
func hashUserAgent(userAgent string) string {
	h := sha256.New()
	h.Write([]byte(userAgent))
	return hex.EncodeToString(h.Sum(nil))
}
func GenerateTokens(userID uuid.UUID, userAgent string) (*TokenDetails, error) {
	td := &TokenDetails{}

	// --- ACCESS TOKEN ---
	accessJTI := uuid.NewString()
	accessExp := time.Now().Add(15 * time.Minute).Unix()

	accessClaims := jwt.MapClaims{
		"user_id": userID,
		"type":    "access",
		"jti":     accessJTI,
		"exp":     accessExp,
		"iat":     time.Now().Unix(),
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	at, err := accessToken.SignedString(jwtSecret)
	if err != nil {
		return nil, err
	}

	// --- REFRESH TOKEN ---
	refreshExp := time.Now().Add(7 * 24 * time.Hour).Unix()
	deviceKey := hashUserAgent(userAgent)

	refreshClaims := jwt.MapClaims{
		"user_id":    userID,
		"type":       "refresh",
		"device_key": deviceKey,
		"exp":        refreshExp,
		"iat":        time.Now().Unix(),
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	rt, err := refreshToken.SignedString(jwtSecret)
	if err != nil {
		return nil, err
	}

	td.AccessToken = at
	td.RefreshToken = rt
	td.AccessJTI = accessJTI
	td.AccessExp = accessExp
	td.RefreshExp = refreshExp

	return td, nil
}

func (m *UserModel) CreateUser(user *RegisterRequest, ipAddress string, userAgent string) (*UserResponse, error) {

	createdAt := time.Now().UTC().Format(time.RFC3339)
	LastLogin := createdAt
	LastModified := createdAt
	RoleId := 1
	query := `INSERT INTO users (username, email, password, firstname, lastname, createdAt, roleId, lastLogin, lastModified, userAgentAtCreation, signupip)
		VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id, username, email, firstname, lastname, avatar, website, createdAt;`

	row := m.DB.QueryRow(query, user.Username, user.Email, user.Password, user.FirstName, user.LastName, createdAt, RoleId, LastLogin, LastModified, userAgent, ipAddress)
	var resp UserResponse
	var avatar sql.NullString
	var website sql.NullString
	err := row.Scan(&resp.Id, &resp.Username, &resp.Email, &resp.FirstName, &resp.LastName, &avatar, &website, &resp.CreatedAt)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	resp.Avatar = avatar.String
	resp.Website = website.String

	return &resp, nil
}

func (m *UserModel) LoginUser(user *LoginRequest, ipAddress string, userAgent string) (*UserResponse, string, string, error) {
	now := time.Now().UTC()
	lastLogin := now
	query := `SELECT id, username, email, firstname, lastname, avatar, website, createdAt, password FROM users WHERE email=$1;`

	row := m.DB.QueryRow(query, user.Email)

	var resp UserResponse
	var avatar sql.NullString
	var website sql.NullString
	var hashedPassword string
	err := row.Scan(&resp.Id, &resp.Username, &resp.Email, &resp.FirstName, &resp.LastName, &avatar, &website, &resp.CreatedAt, &hashedPassword)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, "", "", fmt.Errorf("user with this email does not exist")
		}
		return nil, "", "", err
	}
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(user.Password))
	if err != nil {
		return nil, "", "", fmt.Errorf("wrong email or password")
	}
	resp.Avatar = avatar.String
	resp.Website = website.String
	updateQuery := `UPDATE users SET lastlogin=$1 WHERE id=$2;`
	_, err = m.DB.Exec(updateQuery, lastLogin, resp.Id)

	if err != nil {
		return nil, "", "", err
	}
	tokens, err := GenerateTokens(resp.Id, userAgent)
	if err != nil {
		return nil, "", "", err
	}
	accessToken := tokens.AccessToken
	refreshToken := tokens.RefreshToken

	expiresAt := time.Unix(tokens.RefreshExp, 0).UTC()
	fmt.Println(expiresAt)
	// STORE IN TOKEN BLACKLIST
	storeRefreshToken := `INSERT INTO refresh_tokens (hash_token, user_id, expires_at, issued_at) VALUES ($1, $2, $3, $4);`
	_, err = m.DB.Exec(storeRefreshToken, refreshToken, resp.Id, expiresAt, now)

	if err != nil {
		return nil, "", "", err
	}
	// CHECK SESSION EXISTS or NOT
	verifyDuplicateSession := `SELECT EXISTS (SELECT 1 FROM sessions WHERE user_id=$1 AND useragent=$2 AND ipaddress=$3 AND isactive=true);`
	var exists bool
	err = m.DB.QueryRow(verifyDuplicateSession, resp.Id, userAgent, ipAddress).Scan(&exists)
	if err != nil {
		return nil, "", "", err
	}
	if exists{
		// UPDATE SESSION
		invalidatePreviousAccessToken:=`UPDATE sessions SET updated_at = $1, last_active_at = $2 WHERE user_id = $3 AND useragent = $4 AND ipaddress = $5 AND isactive = true;`
		_, err = m.DB.Exec(invalidatePreviousAccessToken, now, now, resp.Id, userAgent, ipAddress)
		if err != nil {
			return nil, "", "", err
		}
	}
	if !exists {
		// --- CREATE SESSION ---

		createSession := `INSERT INTO sessions (user_id, useragent, ipaddress) VALUES ($1, $2, $3);`
		_, err = m.DB.Exec(createSession, resp.Id, userAgent, ipAddress)
		if err != nil {
			return nil, "", "", err
		}
	}

	return &resp, accessToken, refreshToken, nil
}

func GetUserIDFromBearerToken(bearerToken string, secret string) (string, error) {
	if !strings.HasPrefix(bearerToken, "Bearer ") {
		return "", fmt.Errorf("invalid token format")
	}
	tokenString := strings.TrimPrefix(bearerToken, "Bearer ")
	token, err := jwt.ParseWithClaims(tokenString, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		return "", fmt.Errorf("Failed to parse token")
	}
	if !token.Valid {
		return "", fmt.Errorf("Invalid token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("Failed to parse claims")
	}
	userID, ok := claims["userId"].(string)
	if !ok {
		return "", errors.New("userId not found in token claims")
	}
	return userID, nil
}

func (m *UserModel) GetUser(accessToken string) (*UserInfo, error) {
	userId, err := GetUserIDFromBearerToken(accessToken, string(jwtSecret))
	if err != nil {
		return nil, err
	}
	query := `SELECT username, email, firstname, lastname, avatar, website, roleid, gender, dob, phonenumberone, phonenumbertwo, address, createdat, lastLogin, lastmodified, useractivatedat FROM users WHERE id=$1;`
	row := m.DB.QueryRow(query, userId)

	var resp UserInfo
	var avatar sql.NullString
	var website sql.NullString
	var gender sql.NullString
	var dob sql.NullString
	var roleId int
	var phoneOne sql.NullString
	var phoneTwo sql.NullString
	var address sql.NullString
	var useractivatedat sql.NullString
	err = row.Scan(&resp.Username, &resp.Email, &resp.FirstName, &resp.LastName, &avatar, &website, &roleId, &gender, &dob, &phoneOne, &phoneTwo, &address, &resp.CreatedAt, &resp.LastLogin, &resp.LastModified, &useractivatedat)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}
	getRoleQuery := `SELECT name FROM roles WHERE id=$1;`
	err = m.DB.QueryRow(getRoleQuery, &roleId).Scan(&resp.Role)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("role not found")
		}
		return nil, err
	}
	resp.Avatar = avatar.String
	resp.Website = website.String
	resp.Gender = gender.String
	resp.Dob = dob.String
	resp.PhoneOne = phoneOne.String
	resp.PhoneTwo = phoneTwo.String
	resp.Address = address.String
	resp.UserActivatedAt = useractivatedat.String

	return &resp, nil
}
