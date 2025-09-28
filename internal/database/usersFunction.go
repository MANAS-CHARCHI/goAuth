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
	at, err := accessToken.SignedString([]byte(jwtSecret))
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
	rt, err := refreshToken.SignedString([]byte(jwtSecret))
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
	otp := GenerateUniqueOTP()
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
		otpInsertQuery := `INSERT INTO user_otps (user_id, email, otp, expires_at, created_at) VALUES ($1, $2, $3, $4, $5);`
		expiresAt := time.Now().Add(10 * time.Minute).UTC()
		fmt.Print(email)
		_, err := m.DB.Exec(otpInsertQuery, userID, email, otp, expiresAt, time.Now().UTC())

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

func (m *UserModel) ActivateUser(email string, otp string) error {
	verifyOTPQuery := `SELECT expires_at FROM user_otps WHERE email=$1 AND otp=$2;`
	var expiresAt time.Time
	err := m.DB.QueryRow(verifyOTPQuery, email, otp).Scan(&expiresAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("invalid OTP")
		}
		return err
	}
	if time.Now().After(expiresAt) {
		return fmt.Errorf("OTP has expired")
	}
	query := `UPDATE users SET useractivate = true, useractivatedat = $1 WHERE email = $2;`
	_, err = m.DB.Exec(query, time.Now().UTC().Format(time.RFC3339), email)
	if err != nil {
		return err
	}
	deleteOTPQuery := `DELETE FROM user_otps WHERE email=$1;`
	_, err = m.DB.Exec(deleteOTPQuery, email)
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
		getFailedLoginAttempt := `SELECT failedloginattempts FROM users WHERE id=$1;`
		var failedLoginAttempts int
		err = m.DB.QueryRow(getFailedLoginAttempt, resp.Id).Scan(&failedLoginAttempts)
		if(err != nil) {
			return nil, "", "", err
		}
		if failedLoginAttempts >= 3 {
			updateUser:= `UPDATE users SET failedloginuseragent=$1, failedloginip=$2, failedloginattempts=$3 WHERE id=$4;`
			_, err = m.DB.Exec(updateUser, userAgent, ipAddress, 0, resp.Id)
			if err != nil {
				return nil, "", "", err
			}
			// TODO:- SENT MAIL TO USER THAT SOMEONE IS ATTEMPTING TO LOGIN with this userAgent and ipAddress
		}else{
			updateFailedAttempt := `UPDATE users SET failedloginattempts=$1 WHERE id=$2;`
			_, err = m.DB.Exec(updateFailedAttempt, failedLoginAttempts+1, resp.Id)
			if err != nil {
				return nil, "", "", err
			}
		}
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

func (m *UserModel) ForgotPassword(email string) error {
	query := `SELECT id FROM users WHERE email=$1;`
	var userID uuid.UUID
	err := m.DB.QueryRow(query, email).Scan(&userID)
	if err != nil {
		return err
	}
	otp:=GenerateUniqueOTP()
	checkOTPExistBeforeQuery:=`SELECT EXISTS (SELECT 1 FROM forgot_password_tokens WHERE email=$1);`
	var exists bool
	err = m.DB.QueryRow(checkOTPExistBeforeQuery, email).Scan(&exists)
	if err != nil {
		return err
	}
	if exists {
		updateOTPQuery:=`UPDATE forgot_password_tokens SET otp=$1, expires_at=$2, updated_at=$3 WHERE email=$4;`
		_, err = m.DB.Exec(updateOTPQuery, otp, time.Now().Add(10*time.Minute).UTC(), time.Now().UTC(), email)
		if err != nil {
			return err
		}
	}else{
		storeOTPquery:=` INSERT INTO forgot_password_tokens (email, otp, created_at, expires_at) VALUES ($1, $2, $3, $4);`
		_, err = m.DB.Exec(storeOTPquery, email, otp, time.Now().UTC(), time.Now().Add(10*time.Minute).UTC())
		if err != nil {
			return err
		}
	}
	// TODO:- SEND EMAIL TO USER

	return nil
}
// func (m * UserModel) VerifyForgotPasswordOtp(email string, otp string) error {
// 	query := `SELECT otp, expires_at FROM forgot_password_tokens WHERE email=$1;`
// 	var dbOTP string
// 	var expiresAt time.Time
// 	err := m.DB.QueryRow(query, email).Scan(&dbOTP, &expiresAt)
// 	if err != nil {
// 		if errors.Is(err, sql.ErrNoRows) {
// 			return fmt.Errorf("no OTP found for this email")
// 		}
// 		return err
// 	}
// 	if otp != dbOTP {
// 		return fmt.Errorf("invalid OTP")
// 	}
// 	if time.Now().After(expiresAt) {
// 		return fmt.Errorf("OTP has expired")
// 	}
// 	updateQueryToVerified := `UPDATE forgot_password_tokens SET isverified = true, updated_at = $1 WHERE email = $2;`
// 	_, err = m.DB.Exec(updateQueryToVerified, time.Now().UTC(), email)
// 	if err != nil {
// 		return err
// 	}
// 	return nil
	
// }
func (m * UserModel) ChangeForgotPassword(email string, otp string, newPassword string) error {
	query := `SELECT otp, expires_at FROM forgot_password_tokens WHERE email=$1;`
	var dbOTP string
	var expiresAt time.Time
	err := m.DB.QueryRow(query, email).Scan(&dbOTP, &expiresAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("no OTP found for this email")
		}
		return err
	}
	if otp != dbOTP {
		return fmt.Errorf("invalid OTP")
	}
	if time.Now().After(expiresAt) {
		return fmt.Errorf("OTP has expired")
	}

	previousPasswords:=`SELECT password, lastpassword FROM users WHERE email=$1;`
	var currentPassword string
	var lastPassword sql.NullString

	err = m.DB.QueryRow(previousPasswords, email).Scan(&currentPassword, &lastPassword)
	if err != nil {
		return err
	}
	// Verify old password matches current password from ChangePasswordRequest
	err = bcrypt.CompareHashAndPassword([]byte(currentPassword), []byte(newPassword))
	if err == nil {
		return fmt.Errorf("new password cannot be the same as last 2 passwords")
	}
	// Ensure new password is not same as current password
	err = bcrypt.CompareHashAndPassword([]byte(lastPassword.String), []byte(newPassword))
	if err == nil {
		return fmt.Errorf("new password cannot be the same as last 2 passwords")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	query = `UPDATE users SET password=$1, lastpassword=$2 WHERE email=$3;`
	_, err = m.DB.Exec(query, hashedPassword, currentPassword, email)
	if err != nil {
		return err
	}
	removeOtpQuery := `DELETE FROM forgot_password_tokens WHERE email=$1;`
	_, err = m.DB.Exec(removeOtpQuery, email)
	if err != nil {
		return err
	}
	return nil	
}

func (m *UserModel) ChangePassword(accessToken string, req *ChangePasswordRequest) (string, error) {
	userId, err := GetUserIDFromBearerToken(accessToken, string(jwtSecret))
	if err != nil {
		return "", err
	}
	query:=`SELECT password, lastpassword FROM users WHERE id=$1;`
	var currentPassword string
	var lastPassword sql.NullString

	err = m.DB.QueryRow(query, userId).Scan(&currentPassword, &lastPassword)
	if err != nil {
		return "", err
	}
	// Verify old password matches current password from ChangePasswordRequest
	err = bcrypt.CompareHashAndPassword([]byte(currentPassword), []byte(req.OldPassword))
	if err != nil {
		return "", fmt.Errorf("wrong old password")
	}
	// Ensure new password is not same as current password
	err = bcrypt.CompareHashAndPassword([]byte(currentPassword), []byte(req.NewPassword))
	if err == nil {
		return "", fmt.Errorf("new password cannot be the same as the current password")
	}
	// Ensure new password is not same as last password
	err = bcrypt.CompareHashAndPassword([]byte(lastPassword.String), []byte(req.NewPassword))
	if err == nil {
		return "", fmt.Errorf("new password cannot be the same as the last password")
	}
	// Hash the new password
	hashedNewPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash new password: %v", err)
	}
	updateQuery := `UPDATE users SET password=$1, lastpassword=$2, passwordchangedat=$3 WHERE id=$4;`
	_, err = m.DB.Exec(updateQuery, string(hashedNewPassword), currentPassword, time.Now().UTC().Format(time.RFC3339), userId)
	if err != nil {
		return "", fmt.Errorf("failed to update password: %v", err)
	}
	return "Password changed successfully", nil
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

func (m *UserModel) RefreshTokens(refreshToken string, ipAddress string, userAgent string) (*UserResponse, string, string, error) {
	ctx := context.Background()
	// PARSE REFRESH TOKEN
	fmt.Print("here")
	token, err := jwt.ParseWithClaims(refreshToken, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to parse token: %w", err)
	}
	if !token.Valid {
		return nil, "", "", fmt.Errorf("invalid token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, "", "", errors.New("failed to parse claims")
	}
	tokenType, ok := claims["type"].(string)
	if !ok || tokenType != "refresh" {
		return nil, "", "", errors.New("invalid token type")
	}
	userIdStr, ok := claims["userId"].(string)
	if !ok {
		return nil, "", "", errors.New("userId not found in token claims")
	}
	deviceKey, ok := claims["device_key"].(string)
	if !ok {
		return nil, "", "", errors.New("device_key not found in token claims")
	}
	if deviceKey != hashUserAgent(userAgent) {
		return nil, "", "", errors.New("refresh token does not match the device")
	}
	// CHECK IF REFRESH TOKEN IS REVOKED OR EXPIRED
	checkRefreshToken := `SELECT EXISTS (SELECT 1 FROM refresh_tokens WHERE user_id=$1 AND hash_token=$2 AND revoked=false AND expires_at > NOW());`
	var exists bool
	err = m.DB.QueryRow(checkRefreshToken, userIdStr, refreshToken).Scan(&exists)
	if err != nil {
		return nil, "", "", err
	}
	if !exists {
		return nil, "", "", fmt.Errorf("invalid or expired refresh token")
	}
	// GET USER DETAILS
	query := `SELECT id, username, email, firstname, lastname, avatar, website, createdAt FROM users WHERE id=$1;`
	row := m.DB.QueryRow(query, userIdStr)

	var resp UserResponse
	var avatar sql.NullString
	var website sql.NullString
	err = row.Scan(&resp.Id, &resp.Username, &resp.Email, &resp.FirstName, &resp.LastName, &avatar, &website, &resp.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, "", "", fmt.Errorf("user not found")
		}
		return nil, "", "", err
	}
	resp.Avatar = avatar.String
	resp.Website = website.String

	// GENERATE NEW TOKENS
	tokens, err := GenerateTokens(resp.Id, userAgent)
	if err != nil {
		return nil, "", "", err
	}
	newAccessToken := tokens.AccessToken
	newRefreshToken := tokens.RefreshToken

	expiresAt := time.Unix(tokens.RefreshExp, 0).UTC()
	now := time.Now().UTC()
	// STORE NEW REFRESH TOKEN
	storeRefreshToken := `INSERT INTO refresh_tokens (hash_token, user_id, expires_at, issued_at) VALUES ($1, $2, $3, $4);`
	_, err = m.DB.Exec(storeRefreshToken, newRefreshToken, resp.Id, expiresAt, now)
	if err != nil {
		return nil, "", "", err
	}
	// REVOKE OLD REFRESH TOKEN
	revokeOldRefreshToken := `UPDATE refresh_tokens SET revoked = true WHERE user_id = $1 AND hash_token = $2;`
	_, err = m.DB.Exec(revokeOldRefreshToken, resp.Id, refreshToken)
	if err != nil {
		return nil, "", "", err
	}
	// EXTRACT JTI AND STORE
	jti, err := GetJtiFromToken(newAccessToken)
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
	return &resp, newAccessToken, newRefreshToken, nil
}

func (m *UserModel) UpdateUser(accessToken string, user *UpdateUserRequest) (*UserResponse, error) {
	userId, err := GetUserIDFromBearerToken(accessToken, string(jwtSecret))
	if err != nil {
		return nil, err
	}
	updateUser := `UPDATE users SET firstname=$1, lastname=$2, username=$3, avatar=$4, website=$5, gender=$6, dob=$7, phonenumberone=$8, phonenumbertwo=$9, address=$10, updatedat=NOW() WHERE id=$11;`
	_, err = m.DB.Exec(updateUser, user.FirstName, user.LastName, user.Username, user.Avatar, user.Website, user.Gender, user.Dob, user.PhoneOne, user.PhoneTwo, user.Address, userId)
	if err != nil {
		return nil, err
	}
	query := `SELECT id, username, email, firstname, lastname, avatar, website, createdAt FROM users WHERE id=$1;`
	row := m.DB.QueryRow(query, userId)

	var resp UserResponse
	var avatar sql.NullString
	var website sql.NullString
	err = row.Scan(&resp.Id, &resp.Username, &resp.Email, &resp.FirstName, &resp.LastName, &avatar, &website, &resp.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}
	resp.Avatar = avatar.String
	resp.Website = website.String
	return &resp, nil
}