package config

import (
	"os"

	_ "github.com/joho/godotenv/autoload"
)

type Config struct {
	Database struct {
		Host     string
		Username string
		Password string
		Database string
	}
	Recaptcha struct {
		Secret string
	}
	ZeptoMail struct {
		EmailToken string
	}
	TLS struct {
		PrivateKeyPath  string
		CertificatePath string
	}
	Logger struct {
		LogLevel string
	}
	Production    bool
	SpamhausToken string
}

func New() *Config {
	cfg := &Config{}

	cfg.Database.Database = os.Getenv("POSTGRES_DATABASE")
	cfg.Database.Host = os.Getenv("POSTGRES_HOST")
	cfg.Database.Username = os.Getenv("POSTGRES_USER")
	cfg.Database.Password = os.Getenv("POSTGRES_PASSWORD")

	cfg.Recaptcha.Secret = os.Getenv("CAPTCHA_SECRET")

	cfg.ZeptoMail.EmailToken = os.Getenv("MAIL_TOKEN")

	cfg.TLS.CertificatePath = os.Getenv("CERTIFICATE")
	cfg.TLS.PrivateKeyPath = os.Getenv("PRIVATE_KEY")

	cfg.Logger.LogLevel = getOrDefault("LOG_LEVEL", "debug")

	cfg.Production = getOrDefault("PRODUCTION", "true") == "true"
  cfg.SpamhausToken = os.Getenv("SPAMHAUS_TOKEN")

	return cfg
}

func getOrDefault(variable string, def string) string {
	result, ok := os.LookupEnv(variable)
	if !ok {
		return def
	}
	return result
}
