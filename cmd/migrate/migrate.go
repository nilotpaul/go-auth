package main

import (
	"log"
	"os"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/nilotpaul/go-api/config"
	store "github.com/nilotpaul/go-api/internal/store/db"

	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/lib/pq"
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

	driver, dbErr := postgres.WithInstance(db, &postgres.Config{})

	if dbErr != nil {
		log.Fatal("Failed to create migrations: DB conn error ", dbErr)
	}

	m, err := migrate.NewWithDatabaseInstance(
		"file://cmd/migrate/migrations",
		"postgres",
		driver)

	if err != nil {
		log.Fatal("Failed to create migrations: ", err)
	}

	cmd := os.Args[(len(os.Args) - 1)]

	if cmd == "up" {
		if err := m.Up(); err != nil && err != migrate.ErrNoChange {
			log.Fatal(err)
		}
	}

	if cmd == "down" {
		if err := m.Down(); err != nil && err != migrate.ErrNoChange {
			log.Fatal(err)
		}
	}

	log.Print("Done!")
}
