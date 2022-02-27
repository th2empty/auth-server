package utils

import (
	"crypto/sha1"
	"fmt"
	"github.com/spf13/viper"
	"github.com/th2empty/auth_service/configs"
)

var (
	_ = configs.InitConfig()

	salt = viper.GetString("auth.salt")
)

func GeneratePasswordHash(password string) string {
	hash := sha1.New()
	hash.Write([]byte(password))

	return fmt.Sprintf("%x", hash.Sum([]byte(salt)))
}
