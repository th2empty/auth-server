package repository

import (
	"github.com/jmoiron/sqlx"
	"github.com/th2empty/auth_service/pkg/models"
)

type Authorization interface {
	CreateUser(user models.User) (int, error)
	GetUser(username, password string) (models.User, error)
	GetUserById(id uint) (models.User, error)
	GetSessions(ownerId uint) ([]models.Session, error)
	GetSessionById(id uint) (models.Session, error)
	AddSession(session models.Session, historyItem models.SessionHistoryItem) (uint, error)
	UpdateSession(session models.Session) error
	GetSessionsDetails(userId uint) ([]models.SessionItem, error)
	Logout(sessionId uint) error
}

type Repository struct {
	Authorization
}

func NewRepository(db *sqlx.DB) *Repository {
	return &Repository{
		Authorization: NewAuthPostgres(db),
	}
}
