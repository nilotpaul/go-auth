package service

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/nilotpaul/go-api/types"
	"github.com/nilotpaul/go-api/utils"
	"golang.org/x/crypto/bcrypt"
)

type UserStore struct {
	db *sql.DB
}

func NewUserStore(db *sql.DB) *UserStore {
	return &UserStore{
		db: db,
	}
}

func (us *UserStore) GetUserByEmail(email string) (*types.User, error) {
	rows, err := us.db.Query("SELECT id, email, username, created_at, updated_at FROM users WHERE email = $1", email)

	if err != nil {
		return nil, err
	}

	u, scanErr := scanRows(rows)

	if scanErr != nil {
		return nil, scanErr
	}

	return u, nil
}

func (us *UserStore) GetUserByEmailWithPass(email string) (*types.UserWithPassword, error) {
	rows, err := us.db.Query("SELECT id, email, username, hashed_password, created_at, updated_at FROM users WHERE email = $1", email)

	if err != nil {
		return nil, err
	}

	user := new(types.UserWithPassword)
	for rows.Next() {
		err := rows.Scan(
			&user.ID,
			&user.Email,
			&user.Username,
			&user.HashedPassword,
			&user.Created_at,
			&user.Updated_at,
		)
		if err != nil {
			return nil, err
		}
	}

	return user, nil
}

func (us *UserStore) GetUserByUsername(username string) (*types.User, error) {
	rows, err := us.db.Query("SELECT id, email, username, created_at, updated_at FROM users WHERE username = $1", username)

	if err != nil {
		return nil, err
	}

	u, scanErr := scanRows(rows)

	if scanErr != nil {
		return nil, scanErr
	}

	return u, nil
}

func (us *UserStore) GetUserByToken(r *http.Request) (*types.UserWithRefreshToken, error) {
	tokenCookie, err := r.Cookie("refresh_token")
	token := tokenCookie.Value

	if err != nil || len(token) == 0 {
		return nil, err
	}

	rows, err := us.db.Query("SELECT id, email, username, refresh_token, created_at, updated_at FROM users WHERE refresh_token = $1", token)

	if err != nil {
		return nil, err
	}

	user := new(types.UserWithRefreshToken)

	for rows.Next() {
		err := rows.Scan(
			&user.ID,
			&user.Email,
			&user.Username,
			&user.RefreshToken,
			&user.Created_at,
			&user.Updated_at,
		)

		if err != nil {
			return nil, err
		}
	}

	return user, nil
}

func (us *UserStore) CreateUser(u types.RegisterPayload) error {
	hPass, err := hashPassword([]byte(u.Password))

	if err != nil {
		return err
	}

	res, err := us.db.Exec("INSERT INTO users (email, username, hashed_password) VALUES ($1, $2, $3)", u.Email, u.Username, hPass)

	if err != nil {
		return err
	}

	if num, err := res.RowsAffected(); err != nil || num == 0 {
		return err
	}

	return nil
}

func (us *UserStore) GenerateAndSignRefreshToken(privKeyPath string, userID string) (string, error) {
	claims := jwt.MapClaims{
		"sub":  userID,
		"exp":  time.Now().Add(time.Minute * 5).Unix(), // expires in 5 mins
		"type": "refresh_token",
	}

	privKey, err := utils.LoadPrivateKey(privKeyPath)

	if err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenStr, err := token.SignedString(privKey)

	if err != nil {
		return "", err
	}

	res, err := us.db.Exec("UPDATE users SET refresh_token = $1 WHERE id = $2", tokenStr, userID)

	if err != nil {
		return "", err
	}

	if num, err := res.RowsAffected(); err != nil || num == 0 {
		return "", err
	}

	return tokenStr, nil
}

func (us *UserStore) GenerateAccessToken(privKeyPath string, userID string) (string, error) {
	claims := jwt.MapClaims{
		"sub":  userID,
		"exp":  time.Now().Add(time.Minute).Unix(), // expires in 1 min
		"type": "access_token",
	}

	privKey, err := utils.LoadPrivateKey(privKeyPath)

	if err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenStr, err := token.SignedString(privKey)

	if err != nil {
		return "", err
	}

	return tokenStr, nil
}

func (us *UserStore) InvalidateSession(w http.ResponseWriter, accessToken string) {
	utils.ClearAccessToken(w)

	accessTokenCookie := &http.Cookie{
		Name:     "access_token",
		Value:    accessToken,
		Path:     "/",
		Expires:  time.Now().Add(time.Minute), // expires in 1 minute
		HttpOnly: true,
	}

	http.SetCookie(w, accessTokenCookie) // reset access token
}

func (us *UserStore) ClearSession(w http.ResponseWriter) {
	refreshTokenCookie := &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/",
		Expires:  time.Now().Add(-5 * time.Hour),
		HttpOnly: true,
	}

	utils.ClearAccessToken(w)
	http.SetCookie(w, refreshTokenCookie)
}

func (us *UserStore) ComparePassword(hPass []byte, pass []byte) error {
	err := bcrypt.CompareHashAndPassword(hPass, pass)

	if err != nil {
		return err
	}

	return nil
}

func hashPassword(pass []byte) ([]byte, error) {
	hPass, err := bcrypt.GenerateFromPassword(pass, 10)

	if err != nil {
		return nil, err
	}

	return hPass, nil
}

func scanRows(rows *sql.Rows) (*types.User, error) {
	user := new(types.User)

	for rows.Next() {
		err := rows.Scan(
			&user.ID,
			&user.Email,
			&user.Username,
			&user.Created_at,
			&user.Updated_at,
		)
		if err != nil {
			return nil, err
		}
	}
	return user, nil
}
