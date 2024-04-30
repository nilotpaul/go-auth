package main

import (
	"log"

	"github.com/nilotpaul/go-auth/api"
	"github.com/nilotpaul/go-auth/config"
	"github.com/nilotpaul/go-auth/internal/store/db"
)

const envPath string = "./.env"

func main() {
	cfg := config.LoadConfig()

	db, err := db.NewDBStore(db.DBConfig{
		Name:     cfg.DBName,
		User:     cfg.DBUser,
		Password: cfg.DBPassword,
		Host:     cfg.DBHost,
		Port:     cfg.DBPort,
	})

	if err != nil {
		defer db.Close()
	}

	server := api.NewAPISever(cfg.Port, db, cfg)

	if err := server.Run(); err != nil {
		log.Fatal(err)
	}
}
