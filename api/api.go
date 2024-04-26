package api

import (
	"database/sql"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	api "github.com/nilotpaul/go-api/api/routes"
	"github.com/nilotpaul/go-api/config"
	service "github.com/nilotpaul/go-api/service/user"
)

type APIServer struct {
	listenAddr string
	db         *sql.DB
	cfg        *config.Config
}

func NewAPISever(listenAddr string, db *sql.DB, cfg *config.Config) *APIServer {
	return &APIServer{
		listenAddr: listenAddr,
		db:         db,
		cfg:        cfg,
	}
}

func (s *APIServer) Run() error {
	router := mux.NewRouter()
	subRouter := router.PathPrefix("/api/v1").Subrouter()

	userStore := service.NewUserStore(s.db)

	apiHandler := api.NewHandler(userStore, s.cfg)
	apiHandler.RegisterRoutes(subRouter)

	log.Printf("Server started on http://localhost:%s", s.listenAddr)

	return http.ListenAndServe(":"+s.listenAddr, router)
}
