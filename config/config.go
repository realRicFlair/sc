package config

import "os"

type Config struct {
	BaseDir string
	FileKey []byte
	Port    string
}
type configInterface interface {
	LoadConfig() (*Config, error)
}

func LoadConfig() (*Config, error) {
	var err error
	cfg := &Config{
		BaseDir: "./",
		FileKey: []byte("secret"),
		Port:    "8080",
	}

	cfg.BaseDir, err = os.Getwd()
	if err != nil {
		cfg.BaseDir = "./"
	}

	if v := os.Getenv("PORT"); v != "" {
		cfg.Port = v
	}
	//env for filekey
	if v := os.Getenv("fileKey"); v != "" {
		cfg.FileKey = []byte(v)
	}

	return cfg, nil
}
