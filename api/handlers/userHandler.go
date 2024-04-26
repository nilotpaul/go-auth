package api

import (
	"net/http"

	"github.com/nilotpaul/go-api/types"
	"github.com/nilotpaul/go-api/utils"
)

type UserHandler struct {
	types.UserStore
}

func HandleUser(store types.UserStore) *UserHandler {
	return &UserHandler{UserStore: store}
}

func (h *UserHandler) GetSensitiveInfo(w http.ResponseWriter, r *http.Request) {
	utils.WriteJSON(w, http.StatusOK, "OK")
}
