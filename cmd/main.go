package main

import (
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/spf13/viper"
	authServer "github.com/th2empty/auth_service"
	"github.com/th2empty/auth_service/configs"
	"github.com/th2empty/auth_service/pkg/handler"
	"github.com/th2empty/auth_service/pkg/logging"
	"github.com/th2empty/auth_service/pkg/repository"
	"github.com/th2empty/auth_service/pkg/service"
	"os"
	"strings"
)

var (
	log = logging.GetLogger()
)

// @title           Auth Server API
// @version         1.0.0
// @description     Server for authentication

// @license.name  MIT License

// @host      localhost:9000
// @BasePath  /

// @securityDefinitions.apiKey  AuthApiKey
// @in header
// @name Authorization

// @securityDefinitions.apiKey  RefreshApiKey
// @in header
// @name Authorization
func main() {
	if err := configs.InitConfig(); err != nil {
		log.Fatal(err)
	}

	if err := godotenv.Load(); err != nil {
		log.Fatal(err)
	}

	db, err := repository.NewPostgresDB(repository.Config{
		Host:     viper.GetString("db.host"),
		Port:     viper.GetString("db.port"),
		Username: viper.GetString("db.username"),
		Password: os.Getenv("DB_PASSWORD"),
		DBName:   viper.GetString("db.dbname"),
		SSLMode:  viper.GetString("db.sslmode"),
	})
	if err != nil {
		log.Fatal(err)
	}

	repos := repository.NewRepository(db)
	services := service.NewService(repos)
	handlers := handler.NewHandler(services)

	if strings.EqualFold(viper.GetString("logging.format"), "json") {
		//log.SetFormatter(new(log.JSONFormatter))
		log.Error("changing logger format is unavailable for now")
	}

	srv := new(authServer.Server)
	if err := srv.Run(viper.GetString("port"), handlers.InitRoutes()); err != nil {
		log.Fatal(err)
	}
}
