package types

import (
	"net/http"
	"time"
)

type UserStore interface {
	GetUserByEmail(email string) (*User, error)
	GetUserByEmailWithPass(email string) (*UserWithPassword, error)
	GetUserByUsername(username string) (*User, error)
	GetUserByToken(r *http.Request) (*UserWithRefreshToken, error)
	CreateUser(user RegisterPayload) error
	ComparePassword(hPass []byte, pass []byte) error
	GenerateAndSignRefreshToken(privKeyPath string, userID string) (string, error)
	GenerateAccessToken(privKeyPath string, userID string) (string, error)
	InvalidateSession(w http.ResponseWriter, accessToken string)
	ClearSession(w http.ResponseWriter)
}

type User struct {
	ID         []uint8   `json:"id"`
	Email      string    `json:"email"`
	Username   string    `json:"username"`
	Created_at time.Time `json:"created_at"`
	Updated_at time.Time `json:"updated_at"`
}

type UserWithPassword struct {
	User
	HashedPassword string `json:"hashed_password"`
}

type UserWithRefreshToken struct {
	User
	RefreshToken []byte `json:"refresh_token"`
}
