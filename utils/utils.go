package utils

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
)

type FieldError struct {
	Field string `json:"field"`
	Error string `json:"error"`
}

func ParseJSON(r *http.Request, payload any) error {
	if r.Body == nil {
		return fmt.Errorf("invalid payload")
	}

	return json.NewDecoder(r.Body).Decode(payload)
}

func WriteJSON(w http.ResponseWriter, status int, payload any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	return json.NewEncoder(w).Encode(payload)
}

func ValidateInput(payload interface{}) *FieldError {
	validate := validator.New(validator.WithRequiredStructEnabled())

	if valErr := validate.Struct(payload); valErr != nil {
		for _, err := range valErr.(validator.ValidationErrors) {
			return getErrorMessage(err)
		}
	}

	return nil
}

func getErrorMessage(valErr validator.FieldError) *FieldError {
	switch valErr.Tag() {
	case "min":
		return &FieldError{
			Field: valErr.Field(),
			Error: "at least 6 character(s) required",
		}
	case "eqfield":
		return &FieldError{
			Field: valErr.Field(),
			Error: "input do no match",
		}
	case "email":
		return &FieldError{
			Field: valErr.Field(),
			Error: "invalid email",
		}
	case "required":
		return &FieldError{
			Field: valErr.Field(),
			Error: "required",
		}
	default:
		return &FieldError{
			Field: valErr.Field(),
			Error: valErr.Error(),
		}
	}
}

func LoadPublicKey(filePath string) (*rsa.PublicKey, error) {
	key, err := os.ReadFile(filePath)

	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(key)

	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode the public key")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)

	if err != nil {
		return nil, err
	}

	if rsaPubKey, ok := pubKey.(*rsa.PublicKey); ok {
		return rsaPubKey, nil
	} else {
		return nil, fmt.Errorf("failed to assert public key as *rsa.PublicKey")
	}
}

func LoadPrivateKey(filePath string) (*rsa.PrivateKey, error) {
	key, err := os.ReadFile(filePath)

	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(key)

	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode the private key")
	}

	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)

	if err != nil {
		return nil, err
	}

	if rsaPrivKey, ok := privKey.(*rsa.PrivateKey); ok {
		return rsaPrivKey, nil
	} else {
		return nil, fmt.Errorf("failed to assert private key as *rsa.PrivateKey")
	}
}

func SetLoginToken(w http.ResponseWriter, accessToken string, refreshToken string) {
	accessTokenCookie := &http.Cookie{
		Name:     "access_token",
		Value:    accessToken,
		Path:     "/",
		Expires:  time.Now().Add(time.Minute), // expires in 1 minute
		HttpOnly: true,
	}
	refreshTokenCookie := &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Path:     "/",
		Expires:  time.Now().Add(time.Minute * 5), // expires in 5 minute
		HttpOnly: true,
	}

	http.SetCookie(w, accessTokenCookie)
	http.SetCookie(w, refreshTokenCookie)
}

func GetTokenFromReq(r *http.Request) string {
	jwtHeader := r.Header.Get("Authorization")
	token := strings.Split(jwtHeader, " ")[1]

	if (len(jwtHeader) | len(token)) == 0 {
		return ""
	}

	return token
}

func GetTokenFromCookie(r *http.Request) string {
	cookieToken, err := r.Cookie("access_token")
	token := cookieToken.Value

	if err != nil || len(token) == 0 {
		return ""
	}

	return token
}

func ParseUserFromJWT(tokenJWT *jwt.Token) string {
	claims := tokenJWT.Claims.(jwt.MapClaims)

	userID := claims["sub"].(string)

	if len(userID) == 0 {
		return ""
	}

	return userID
}

func VerifyJWT(tokenStr string, pubKeyPath string, tokenType string) (*jwt.Token, bool, error) {
	pubKey, err := LoadPublicKey(pubKeyPath)

	if err != nil {
		return nil, false, err
	}

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("invalid signing method: %v ", token.Method)
		}
		return pubKey, nil
	})

	if err != nil {
		return nil, false, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)

	if !ok {
		return nil, false, fmt.Errorf("failed to extract claims")
	}

	tType, exists := claims["type"].(string)

	if !exists {
		return nil, false, fmt.Errorf("type not found in claims")
	}

	if tType != tokenType {
		return nil, false, fmt.Errorf("invalid token type: %s", tType)
	}

	if !token.Valid {
		return nil, false, fmt.Errorf("invalid token")
	}

	return token, token.Valid, nil
}

func ClearAccessToken(w http.ResponseWriter) {
	accessTokenCookie := &http.Cookie{
		Name:     "access_token",
		Value:    "",
		Path:     "/",
		Expires:  time.Now().Add(-1 * time.Hour),
		HttpOnly: true,
	}

	http.SetCookie(w, accessTokenCookie) // clear access token cookie
}
