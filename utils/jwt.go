package utils

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

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
