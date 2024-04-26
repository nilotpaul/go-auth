package config

import (
	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	Port           string `envconfig:"PORT"`
	DBPassword     string `envconfig:"DB_PASSWORD"`
	DBUser         string `envconfig:"DB_USER"`
	DBName         string `envconfig:"DB_NAME"`
	DBHost         string `envconfig:"DB_HOST"`
	DBPort         string `envconfig:"DB_PORT"`
	PrivateKeyPath string `envconfig:"PRIVATE_KEY_PATH"`
	PublicKeyPath  string `envconfig:"PUBLIC_KEY_PATH"`
}

func loadEnv() (*Config, error) {
	var cfg Config
	err := godotenv.Load()

	if err != nil {
		return nil, err
	}

	envErr := envconfig.Process("", &cfg)

	if envErr != nil {
		return nil, envErr
	}

	return &cfg, nil
}

func LoadConfig() *Config {
	cfg, err := loadEnv()

	if err != nil {
		panic(err)
	}

	return cfg
}
