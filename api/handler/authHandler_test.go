package handler_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/nilotpaul/go-auth/api/handler"
	"github.com/nilotpaul/go-auth/api/route"
	"github.com/nilotpaul/go-auth/config"
	"github.com/nilotpaul/go-auth/types"
	"github.com/nilotpaul/go-auth/utils"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

type mockUserStore struct{}

func TestLoginRoute(t *testing.T) {
	cfg := &config.Config{
		Port:           "3000",
		PrivateKeyPath: "../../cert/private_key.pem",
		PublicKeyPath:  "../../cert/public_key.pem",
		DBPassword:     "",
		DBUser:         "",
		DBName:         "",
		DBHost:         "",
		DBPort:         "",
	}
	userStore := &mockUserStore{}

	h := route.NewHandler(userStore, cfg)
	authApi := handler.HandleAuth(h.UserStore, h.Cfg)

	r := mux.NewRouter()
	h.RegisterRoutes(r)

	// Test case: invalid email
	t.Run("should fail if invalid email is passed", func(t *testing.T) {
		user := &types.LoginPayload{
			Email:    "testgmail.com",
			Password: "123456",
		}
		payload, _ := json.Marshal(user)

		req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(payload))
		rr := httptest.NewRecorder()

		authApi.Login(rr, req)

		var res utils.FieldError
		if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
			log.Println(err)
		}

		assert.Equal(t, http.StatusUnprocessableEntity, rr.Code)
		assert.Equal(t, "invalid email", res.Error)
		assert.Equal(t, "Email", res.Field)
	})

	// Test case: not registered email
	t.Run("should fail if the email is not registered", func(t *testing.T) {
		user := &types.LoginPayload{
			Email:    "userdoesntexists@gmail.com",
			Password: "123456",
		}
		payload, _ := json.Marshal(user)

		req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(payload))
		rr := httptest.NewRecorder()

		authApi.Login(rr, req)

		resp := rr.Body.String()

		assert.Equal(t, http.StatusNotFound, rr.Code)
		assert.Equal(t, "\"user not found\"\n", resp)
	})

	t.Run("should fail if password is incorrect", func(t *testing.T) {
		user := &types.LoginPayload{
			Email:    "test@gmail.com",
			Password: "1234567",
		}
		payload, _ := json.Marshal(user)

		req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(payload))
		rr := httptest.NewRecorder()

		authApi.Login(rr, req)

		resp := rr.Body.String()

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Equal(t, "\"invalid credentials\"\n", resp)
	})

	t.Run("should log the user in", func(t *testing.T) {
		user := &types.LoginPayload{
			Email:    "test@gmail.com",
			Password: "123456",
		}
		payload, _ := json.Marshal(user)

		req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(payload))
		rr := httptest.NewRecorder()

		authApi.Login(rr, req)

		resp := rr.Body.String()

		foundCookie := rr.Result().Cookies()[0].Name == "access_token" && rr.Result().Cookies()[1].Name == "refresh_token"

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "\"logged in!\"\n", resp)
		assert.True(t, foundCookie, "cookie(s) not found")
	})

}

func (us *mockUserStore) GetUserByEmail(email string) (*types.User, error) {
	return nil, nil
}

func (us *mockUserStore) GetUserByEmailWithPassword(email string) (*types.UserWithPassword, error) {
	if email == "userdoesntexists@gmail.com" {
		return nil, fmt.Errorf("user not found")
	}

	hashedPass, err := bcrypt.GenerateFromPassword([]byte("123456"), 10)
	if err != nil {
		log.Println("failed to hash the password")
		return nil, err
	}

	u := &types.UserWithPassword{
		User: types.User{
			ID:         []uint8("test_user_id"),
			Email:      "test@gmail.com",
			Username:   "test",
			Created_at: time.Now(),
			Updated_at: time.Now(),
		},
		HashedPassword: string(hashedPass),
	}

	return u, nil
}

func (us *mockUserStore) GetUserByUsername(username string) (*types.User, error) {
	return nil, nil
}

func (us *mockUserStore) GetUserByToken(r *http.Request) (*types.UserWithRefreshToken, error) {
	return nil, nil
}

func (us *mockUserStore) CreateUser(user types.RegisterPayload) error {
	return nil
}

func (us *mockUserStore) ComparePassword(hPass []byte, pass []byte) error {
	err := bcrypt.CompareHashAndPassword(hPass, pass)

	if err != nil {
		return err
	}

	return nil
}

func (us *mockUserStore) GenerateAndSignRefreshToken(privKeyPath string, userID string) (string, error) {
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

	return tokenStr, nil
}

func (us *mockUserStore) GenerateAccessToken(privKeyPath string, userID string) (string, error) {
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

func (us *mockUserStore) InvalidateSession(w http.ResponseWriter, accessToken string) {}

func (us *mockUserStore) ClearSession(w http.ResponseWriter) {}
