package api

import (
	"net/http"

	"github.com/gorilla/mux"
	api "github.com/nilotpaul/go-api/api/handlers"
	middleware "github.com/nilotpaul/go-api/api/middlewares"
	"github.com/nilotpaul/go-api/config"
	"github.com/nilotpaul/go-api/types"
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
	authApi := api.HandleAuth(h.UserStore, h.Cfg)
	userApi := api.HandleUser(h.UserStore)

	authMiddleware := middleware.NewAuthMiddleware(h.UserStore, h.Cfg)

	r.HandleFunc("/login", authMiddleware.WithoutAuth(authApi.Login)).Methods(http.MethodPost)
	r.HandleFunc("/register", authMiddleware.WithoutAuth(authApi.Register)).Methods(http.MethodPost)
	r.HandleFunc("/logout", authMiddleware.WithAuth(authApi.Logout)).Methods(http.MethodPost)
	r.HandleFunc("/refresh", authApi.RefreshToken).Methods(http.MethodGet)

	r.HandleFunc("/sensitive", authMiddleware.WithAuth(userApi.GetSensitiveInfo)).Methods(http.MethodGet)
}
