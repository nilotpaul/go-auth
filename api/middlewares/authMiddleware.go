package api

import (
	"context"
	"log"
	"net/http"

	"github.com/nilotpaul/go-api/config"
	"github.com/nilotpaul/go-api/types"
	"github.com/nilotpaul/go-api/utils"
)

type AuthMiddleware struct {
	types.UserStore
	Cfg *config.Config
}

func NewAuthMiddleware(store types.UserStore, Cfg *config.Config) *AuthMiddleware {
	return &AuthMiddleware{
		UserStore: store,
		Cfg:       Cfg,
	}
}

const UserKey string = "userID"

func (a *AuthMiddleware) WithAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := utils.GetTokenFromCookie(r)

		t, ok, err := utils.VerifyJWT(token, a.Cfg.PublicKeyPath, "access_token")

		if !ok || err != nil {
			log.Println(err)
			utils.WriteJSON(w, http.StatusUnauthorized, "user must be logged in")
			return
		}

		decodedUID := utils.ParseUserFromJWT(t)

		if len(decodedUID) == 0 {
			utils.WriteJSON(w, http.StatusUnauthorized, "user must be logged in")
			return
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, UserKey, decodedUID)
		r = r.WithContext(ctx)

		handler(w, r)
	}
}

func (a *AuthMiddleware) WithoutAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := utils.GetTokenFromCookie(r)

		_, ok, err := utils.VerifyJWT(token, a.Cfg.PublicKeyPath, "access_token")

		if ok && err == nil {
			utils.WriteJSON(w, http.StatusForbidden, "access blocked because you are already logged in")
			return
		}

		handler(w, r)
	}
}
