package db

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

type DBConfig struct {
	Name     string
	User     string
	Password string
	Host     string
	Port     string
}

func NewDBStore(cfg DBConfig) (*sql.DB, error) {
	connStr := fmt.Sprintf("user=%s password=%s host=%s port=%s dbname=%s", cfg.User, cfg.Password, cfg.Host, cfg.Port, cfg.Name)

	db, err := sql.Open("postgres", connStr)

	if err != nil {
		log.Fatal("Failed to connect to DB: ", err)
		return nil, err
	}

	pingErr := db.Ping()

	if pingErr != nil {
		log.Fatal("Ping error: ", pingErr)
		return nil, pingErr
	}

	log.Println("DB Connected")

	return db, nil
}
