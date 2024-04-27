package api

import (
	"net/http"

	"github.com/gorilla/mux"
	api "github.com/nilotpaul/go-auth/api/handler"
	middleware "github.com/nilotpaul/go-auth/api/middleware"
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
	authApi := api.HandleAuth(h.UserStore, h.Cfg)
	userApi := api.HandleUser(h.UserStore)

	// ratelimiter := pkg.NewRateLimiter(5, time.Minute)

	authMiddleware := middleware.NewAuthMiddleware(h.Cfg)
	// rateLimiMiddleware := middleware.NewRateLimitMiddleware(ratelimiter)

	// r.Use(rateLimiMiddleware.WithRateLimit)

	r.HandleFunc("/login", authMiddleware.WithoutAuth(authApi.Login)).Methods(http.MethodPost)
	r.HandleFunc("/register", authMiddleware.WithoutAuth(authApi.Register)).Methods(http.MethodPost)
	r.HandleFunc("/logout", authMiddleware.WithAuth(authApi.Logout)).Methods(http.MethodPost)
	r.HandleFunc("/refresh", authApi.RefreshToken).Methods(http.MethodGet)

	r.HandleFunc("/sensitive", authMiddleware.WithAuth(userApi.GetSensitiveInfo)).Methods(http.MethodGet)
}
