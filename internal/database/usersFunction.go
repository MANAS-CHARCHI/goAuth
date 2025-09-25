package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
)

type UserModel struct {
	DB    *sql.DB
	Redis *redis.Client
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
		"userId": userID,
		"type":   "access",
		"jti":    accessJTI,
		"exp":    accessExp,
		"iat":    time.Now().Unix(),
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
		"userId":     userID,
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

func sendUserOTP(m *UserModel, userID uuid.UUID, email string) (string, error) {
	otp := fmt.Sprintf("%06d", time.Now().UnixNano()%1000000)
	checkUserWithOtpExists := `SELECT EXISTS (SELECT 1 FROM user_otps WHERE user_id=$1);`
	var exists bool
	err := m.DB.QueryRow(checkUserWithOtpExists, userID).Scan(&exists)
	if err != nil {
		return "", err
	}
	if exists {
		updateUserOTP := `UPDATE user_otps SET otp=$1, expires_at=$2, updated_at=$3 WHERE user_id=$4;`
		expiresAt := time.Now().Add(10 * time.Minute).UTC()
		_, err := m.DB.Exec(updateUserOTP, otp, expiresAt, time.Now().UTC(), userID)
		if err != nil {
			return "", err
		}
	} else {
		otpInsertQuery := `INSERT INTO user_otps (user_id, otp, expires_at, created_at) VALUES ($1, $2, $3, $4);`
		expiresAt := time.Now().Add(10 * time.Minute).UTC()
		_, err := m.DB.Exec(otpInsertQuery, userID, otp, expiresAt, time.Now().UTC())
		if err != nil {
			return "", err
		}
	}

	// Send OTP to user's email
	fmt.Printf("OTP for user %s: %s\n", email, otp)

	return otp, nil
}

func (m *UserModel) CreateUser(user *RegisterRequest, ipAddress string, userAgent string) (*UserResponse, error) {

	createdAt := time.Now().UTC().Format(time.RFC3339)
	LastLogin := createdAt
	LastModified := createdAt
	RoleId := 1
	query := `INSERT INTO users (username, email, password, firstname, lastname, createdAt, roleId, lastLogin, lastModified, userAgentAtCreation, signupip, useractivate)
		VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING id, username, email, firstname, lastname, avatar, website, createdAt;`

	row := m.DB.QueryRow(query, user.Username, user.Email, user.Password, user.FirstName, user.LastName, createdAt, RoleId, LastLogin, LastModified, userAgent, ipAddress, false)
	var resp UserResponse
	var avatar sql.NullString
	var website sql.NullString
	err := row.Scan(&resp.Id, &resp.Username, &resp.Email, &resp.FirstName, &resp.LastName, &avatar, &website, &resp.CreatedAt)
	if err != nil {
		return nil, err
	}
	resp.Avatar = avatar.String
	resp.Website = website.String
	go func(userID uuid.UUID, email string) {
		_, err := sendUserOTP(m, userID, email)
		if err != nil {
			log.Printf("sendUserOTP failed: %v", err)
		}
	}(resp.Id, resp.Email)
	return &resp, nil
}

func (m *UserModel) ActivateUser(userID uuid.UUID, otp string) error {
	verifyOTPQuery := `SELECT expires_at FROM user_otps WHERE user_id=$1 AND otp=$2;`
	var expiresAt time.Time
	err := m.DB.QueryRow(verifyOTPQuery, userID, otp).Scan(&expiresAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("invalid OTP")
		}
		return err
	}
	if time.Now().After(expiresAt) {
		return fmt.Errorf("OTP has expired")
	}
	query := `UPDATE users SET useractivate = true, useractivatedat = $1 WHERE id = $2;`
	_, err = m.DB.Exec(query, time.Now().UTC().Format(time.RFC3339), userID)
	if err != nil {
		return err
	}
	deleteOTPQuery := `DELETE FROM user_otps WHERE user_id=$1;`
	_, err = m.DB.Exec(deleteOTPQuery, userID)
	if err != nil {
		return err
	}
	return nil
}

func (m *UserModel) LoginUser(user *LoginRequest, ipAddress string, userAgent string) (*UserResponse, string, string, error) {
	ctx := context.Background()
	now := time.Now().UTC()
	lastLogin := now
	query := `SELECT id, username, email, firstname, lastname, avatar, website, createdAt, password, useractivate FROM users WHERE email=$1;`

	row := m.DB.QueryRow(query, user.Email)

	var resp UserResponse
	var avatar sql.NullString
	var website sql.NullString
	var hashedPassword string
	err := row.Scan(&resp.Id, &resp.Username, &resp.Email, &resp.FirstName, &resp.LastName, &avatar, &website, &resp.CreatedAt, &hashedPassword, &resp.UserActivated)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, "", "", fmt.Errorf("user with this email does not exist")
		}
		return nil, "", "", err
	}
	if !resp.UserActivated {
		return nil, "", "", fmt.Errorf("user is not activated")
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

	// STORE IN TOKEN BLACKLIST
	storeRefreshToken := `INSERT INTO refresh_tokens (hash_token, user_id, expires_at, issued_at) VALUES ($1, $2, $3, $4);`
	_, err = m.DB.Exec(storeRefreshToken, refreshToken, resp.Id, expiresAt, now)

	if err != nil {
		return nil, "", "", err
	}
	// EXTRACT JTI AND STORE
	jti, err := GetJtiFromToken(accessToken)
	if err != nil {
		return nil, "", "", err
	}
	// STORE JTI IN REDIS
	ttl := 15 * time.Minute
	key := "user-jtis:" + jti
	value := "valid"
	err = m.Redis.Set(ctx, key, value, ttl).Err()
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to store JTI in Redis: %w", err)
	}

	// CHECK SESSION EXISTS or NOT
	verifyDuplicateSession := `SELECT EXISTS (SELECT 1 FROM sessions WHERE user_id=$1 AND useragent=$2);`
	var exists bool
	err = m.DB.QueryRow(verifyDuplicateSession, resp.Id, userAgent).Scan(&exists)
	if err != nil {
		return nil, "", "", err
	}
	if exists {
		// UPDATE SESSION
		invalidatePreviousAccessToken := `UPDATE sessions SET updated_at = $1, last_active_at = $2, isactive = true, ipaddress = $3 WHERE user_id = $4 AND useragent = $5;`
		_, err = m.DB.Exec(invalidatePreviousAccessToken, now, now, ipAddress, resp.Id, userAgent)
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
		return "", fmt.Errorf("failed to parse token")
	}
	if !token.Valid {
		return "", fmt.Errorf("invalid token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("failed to parse claims")
	}
	userID, ok := claims["userId"].(string)
	if !ok {
		return "", errors.New("userId not found in token claims")
	}
	tokenType := claims["type"].(string)
	if tokenType != "access" {
		return "", errors.New("invalid token type")
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

func (m *UserModel) Logout(accessToken string, refreshToken string, userAgent string) (string, error) {
	userId, err := GetUserIDFromBearerToken(accessToken, string(jwtSecret))
	if err != nil {
		return "", err
	}
	checkCurrectRefreshToken := `SELECT EXISTS (SELECT 1 FROM refresh_tokens WHERE user_id=$1 AND hash_token=$2 AND revoked=false AND expires_at > NOW());`
	var exists bool
	err = m.DB.QueryRow(checkCurrectRefreshToken, userId, refreshToken).Scan(&exists)
	if err != nil {
		return "", err
	}
	if !exists {
		return "", fmt.Errorf("invalid refresh token")
	}
	removeRefreshToken := `UPDATE refresh_tokens SET revoked = true WHERE user_id = $1 AND hash_token = $2;`
	_, err = m.DB.Exec(removeRefreshToken, userId, refreshToken)
	if err != nil {
		return "", err
	}
	query := `UPDATE sessions SET isactive = false WHERE user_id = $1 AND useragent = $2;`
	_, err = m.DB.Exec(query, userId, userAgent)
	if err != nil {
		return "", err
	}

	jti, err := GetJtiFromToken(accessToken)
	if err != nil {
		return "", err
	}

	// Get and update JTI IN REDIS and make the jti invalid so that any further request with this access token will be rejected
	ttl := 15 * time.Minute
	key := "user-jtis:" + jti
	val, err := m.Redis.Get(context.Background(), key).Result()
	if err != nil || val != "invalid" {
		value := "invalid"
		_ = m.Redis.Set(context.Background(), key, value, ttl).Err()
	}
	return "Successfully logged out", nil
}
