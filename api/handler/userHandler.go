package handler

import (
	"fmt"
	"net/http"

	"github.com/nilotpaul/go-auth/types"
	"github.com/nilotpaul/go-auth/utils"
)

type UserHandler struct {
	types.UserStore
}

func HandleUser(store types.UserStore) *UserHandler {
	return &UserHandler{UserStore: store}
}

func (h *UserHandler) GetSensitiveInfo(w http.ResponseWriter, r *http.Request) {
	uID := utils.GetUserFromCtx(r)

	utils.WriteJSON(w, http.StatusOK, fmt.Sprintf("user id is %s", uID))
}
