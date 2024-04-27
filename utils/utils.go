package utils

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"

	"github.com/go-playground/validator/v10"
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
