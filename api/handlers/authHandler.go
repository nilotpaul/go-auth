package api

import (
	"log"
	"net/http"

	"github.com/nilotpaul/go-api/config"
	"github.com/nilotpaul/go-api/types"
	"github.com/nilotpaul/go-api/utils"
)

type AuthHandler struct {
	UserStore types.UserStore
	Cfg       *config.Config
}

func HandleAuth(store types.UserStore, cfg *config.Config) *AuthHandler {
	return &AuthHandler{
		UserStore: store,
		Cfg:       cfg,
	}
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var payload types.LoginPayload

	if err := utils.ParseJSON(r, &payload); err != nil {
		log.Println(err)
		utils.WriteJSON(w, http.StatusBadRequest, "input parse failed")
		return
	}

	if err := utils.ValidateInput(payload); err != nil {
		utils.WriteJSON(w, http.StatusUnprocessableEntity, err)
		return
	}

	u, err := h.UserStore.GetUserByEmailWithPass(payload.Email)

	if err != nil || u.ID == nil {
		utils.WriteJSON(w, http.StatusNotFound, "user not found")
		return
	}

	if err := h.UserStore.ComparePassword([]byte(u.HashedPassword), []byte(payload.Password)); err != nil {
		utils.WriteJSON(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	refreshToken, err := h.UserStore.GenerateAndSignRefreshToken(h.Cfg.PrivateKeyPath, string(u.ID))

	if err != nil || len(refreshToken) == 0 {
		log.Println(err)
		utils.WriteJSON(w, http.StatusInternalServerError, "failed to generate refresh token")
		return
	}

	accessToken, err := h.UserStore.GenerateAccessToken(h.Cfg.PrivateKeyPath, string(u.ID))

	if err != nil || len(accessToken) == 0 {
		log.Println(err)
		utils.WriteJSON(w, http.StatusInternalServerError, "failed to generate access token")
		return
	}

	utils.SetLoginToken(w, accessToken, refreshToken)

	utils.WriteJSON(w, http.StatusOK, "logged in!")
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var payload types.RegisterPayload

	if err := utils.ParseJSON(r, &payload); err != nil {
		log.Println(err)
		utils.WriteJSON(w, http.StatusBadRequest, "input parse failed")
		return
	}

	if err := utils.ValidateInput(payload); err != nil {
		utils.WriteJSON(w, http.StatusUnprocessableEntity, err)
		return
	}

	u, err := h.UserStore.GetUserByEmail(payload.Email)

	if err != nil {
		utils.WriteJSON(w, http.StatusBadRequest, err.Error())
		return
	}

	if u.ID != nil {
		utils.WriteJSON(w, http.StatusConflict, "account already exists")
		return
	}

	u, err = h.UserStore.GetUserByUsername(payload.Username)

	if err != nil {
		utils.WriteJSON(w, http.StatusBadRequest, err.Error())
		return
	}

	if u.ID != nil {
		utils.WriteJSON(w, http.StatusConflict, "username is taken")
		return
	}

	if err := h.UserStore.CreateUser(payload); err != nil {
		utils.WriteJSON(w, http.StatusInternalServerError, err.Error())
		return
	}

	utils.WriteJSON(w, http.StatusOK, "OK")
}

func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	u, err := h.UserStore.GetUserByToken(r)

	if err != nil || len(u.ID) == 0 {
		log.Println(err)
		utils.WriteJSON(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}

	_, ok, err := utils.VerifyJWT(string(u.RefreshToken), h.Cfg.PublicKeyPath, "refresh_token")

	if !ok || err != nil {
		log.Println(err)
		utils.WriteJSON(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}

	accessToken, err := h.UserStore.GenerateAccessToken(h.Cfg.PrivateKeyPath, string(u.ID))

	if err != nil {
		log.Println(err)
		utils.WriteJSON(w, http.StatusInternalServerError, "failed to generate access key")
		return
	}

	h.UserStore.InvalidateSession(w, accessToken)

	utils.WriteJSON(w, http.StatusOK, "invalidated session!")
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	h.UserStore.ClearSession(w)

	utils.WriteJSON(w, http.StatusOK, "logged out!")

	// Todo: remove user from ctx
}
