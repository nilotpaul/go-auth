package utils

import (
	"net/http"
)

const UserID string = "userID"

func GetUserFromCtx(r *http.Request) string {
	uID, ok := r.Context().Value(UserID).(string)

	if !ok {
		return ""
	}

	return uID
}
