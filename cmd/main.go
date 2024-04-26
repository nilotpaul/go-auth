package main

import (
	"log"

	"github.com/nilotpaul/go-api/api"
	"github.com/nilotpaul/go-api/config"
	store "github.com/nilotpaul/go-api/internal/store/db"
)

func main() {
	cfg := config.LoadConfig()

	db, _ := store.NewDBStore(store.DBConfig{
		Name:     cfg.DBName,
		User:     cfg.DBUser,
		Password: cfg.DBPassword,
		Host:     cfg.DBHost,
		Port:     cfg.DBPort,
	})

	server := api.NewAPISever(cfg.Port, db, cfg)

	if err := server.Run(); err != nil {
		log.Fatal(err)
	}
}
