package route

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/nilotpaul/go-auth/api/handler"
	"github.com/nilotpaul/go-auth/api/middleware"
	"github.com/nilotpaul/go-auth/config"
	"github.com/nilotpaul/go-auth/types"
)

type Handler struct {
	UserStore types.UserStore
	Cfg       *config.Config
}

func NewHandler(store types.UserStore, cfg *config.Config) *Handler {
	return &Handler{
		UserStore: store,
		Cfg:       cfg,
	}
}

func (h *Handler) RegisterRoutes(r *mux.Router) {
	authApi := handler.HandleAuth(h.UserStore, h.Cfg)
	userApi := handler.HandleUser(h.UserStore)

	authMiddleware := middleware.NewAuthMiddleware(h.Cfg)

	r.HandleFunc("/login", authMiddleware.WithoutAuth(authApi.Login)).Methods(http.MethodPost)
	r.HandleFunc("/register", authMiddleware.WithoutAuth(authApi.Register)).Methods(http.MethodPost)
	r.HandleFunc("/logout", authMiddleware.WithAuth(authApi.Logout)).Methods(http.MethodPost)
	r.HandleFunc("/refresh", authApi.RefreshToken).Methods(http.MethodGet)

	r.HandleFunc("/sensitive", authMiddleware.WithAuth(userApi.GetSensitiveInfo)).Methods(http.MethodGet)
}
