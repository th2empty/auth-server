package service

import (
	"github.com/th2empty/auth_service/pkg/models"
	"github.com/th2empty/auth_service/pkg/repository"
)

type Authorization interface {
	CreateUser(user models.User) (int, error)
	GenerateTokens(user models.User, session models.Session) ([]string, error)
	ParseAccessToken(token string) (*AccessTokenClaims, error)
	ParseRefreshToken(token string) (*RefreshTokenClaims, error)
	GetUser(username, password string) (models.User, error)
	GetUserById(id uint) (models.User, error)
	GetSessions(ownerId uint) ([]models.Session, error)
	GetSessionById(id uint) (models.Session, error)
	AddSession(session models.Session) (uint, error)
	UpdateSession(session models.Session) error
	Logout(sessionId uint) error
}

type Service struct {
	Authorization
}

func NewService(repos *repository.Repository) *Service {
	return &Service{
		Authorization: NewAuthService(repos.Authorization),
	}
}
