package repository

import (
	"fmt"
	"github.com/jmoiron/sqlx"
	"github.com/sirupsen/logrus"
	"github.com/th2empty/auth_service/pkg/models"
)

type AuthPostgres struct {
	db *sqlx.DB
}

func NewAuthPostgres(db *sqlx.DB) *AuthPostgres {
	return &AuthPostgres{db: db}
}

func (r *AuthPostgres) CreateUser(user models.User) (int, error) {
	tx, err := r.db.Begin()
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"package":  "repository",
			"file":     "auth_postgres.go",
			"function": "CreateUser",
			"message":  err,
		}).Errorf("error while starting transaction")
		return 0, err
	}

	var id int
	createUserQuery := fmt.Sprintf(`INSERT INTO %s (username, email, password_hash, avatar_id, role_id) 
								values($1, $2, $3, $4, $5) RETURNING id`, usersTable)
	createSettingsQuery := fmt.Sprintf(`INSERT INTO %s (user_id, data_encryption_enabled, cloud_notifications_enabled)
											VALUES($1, $2, $3) RETURNING user_id`, settingsTable)

	row := tx.QueryRow(createUserQuery, user.Username, user.Email, user.Password, user.AvatarId, 0)
	if err := row.Scan(&id); err != nil {
		logrus.WithFields(logrus.Fields{
			"package":  "repository",
			"file":     "auth_postgres.go",
			"function": "CreateUser",
			"message":  err,
		}).Errorf("scan scopies returned error")

		tx.Rollback()
		return 0, err
	}

	_, err = tx.Exec(createSettingsQuery, id, true, true)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"package":  "repository",
			"file":     "auth_postgres.go",
			"function": "CreateUser",
			"message":  err,
		}).Errorf("error while execute query")

		tx.Rollback()
		return 0, err
	}

	return id, tx.Commit()
}

func (r *AuthPostgres) GetUser(username, password string) (models.User, error) {
	var user models.User

	query := fmt.Sprintf("SELECT id FROM %s WHERE username=$1 AND password_hash=$2", usersTable)
	err := r.db.Get(&user, query, username, password)

	return user, err
}

func (r *AuthPostgres) GetUserById(id uint) (models.User, error) {
	var user models.User

	query := fmt.Sprintf("SELECT id, username, email, password_hash, avatar_id, role_id FROM %s WHERE id=$1", usersTable)
	err := r.db.Get(&user, query, id)

	return user, err
}

func (r *AuthPostgres) AddSession(session models.Session, historyItem models.SessionHistoryItem) (uint, error) {
	tx, err := r.db.Begin()
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"package":  "repository",
			"file":     "auth_postgres.go",
			"function": "AddSession",
			"message":  err,
		}).Errorf("error while starting transaction")
		return 0, err
	}

	var id uint
	createSessionQuery := fmt.Sprintf(`INSERT INTO %s (user_id, refresh_token, refresh_uuid, issused_at) 
								values($1, $2, $3, $4) RETURNING id`, sessionsTable)
	addSessionToHistoryQuery := fmt.Sprintf(`INSERT INTO %s (app_id, ip_address, city, os, time)
													VALUES($1, $2, $3, $4, $5) RETURNING id`, sessionsHistoryTable)

	row := tx.QueryRow(createSessionQuery,
		session.UserId, session.RefreshToken, session.RefreshUUID, session.IssusedAt)
	if err := row.Scan(&id); err != nil {
		logrus.WithFields(logrus.Fields{
			"package":  "repository",
			"file":     "auth_postgres.go",
			"function": "AddSession",
			"message":  err,
		}).Errorf("scan scopies returned error")

		tx.Rollback()
		return 0, err
	}

	_, err = tx.Exec(addSessionToHistoryQuery,
		historyItem.AppId, historyItem.IpAddress, historyItem.City, historyItem.OS, historyItem.Time)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"package":  "repository",
			"file":     "auth_postgres.go",
			"function": "AddSession",
			"message":  err,
		}).Errorf("error while execute query")

		tx.Rollback()
		return 0, err
	}

	return id, tx.Commit()
}

func (r *AuthPostgres) UpdateSession(session models.Session) error {
	tx, err := r.db.Begin()
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"package":  "repository",
			"file":     "auth_postgres.go",
			"function": "UpdateSession",
			"message":  err,
		}).Errorf("error while starting transaction")
		return err
	}

	updateSessionQuery := fmt.Sprintf(`UPDATE %s SET refresh_token=$1, refresh_uuid=$2, issused_at=$3 WHERE id=$4`, sessionsTable)

	_, err = tx.Exec(updateSessionQuery, session.RefreshToken, session.RefreshUUID, session.IssusedAt, session.SessionId)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"package":  "repository",
			"file":     "auth_postgres.go",
			"function": "UpdateSession",
			"message":  err,
		}).Errorf("scan scopies returned error")

		tx.Rollback()
		return err
	}

	return tx.Commit()
}

func (r *AuthPostgres) GetSessions(ownerId uint) ([]models.Session, error) {
	var sessions []models.Session

	query := fmt.Sprintf(
		"SELECT id, user_id, refresh_token, refresh_uuid, issused_at from %s WHERE user_id=$1", sessionsTable)

	//err := r.db.Get(&sessions, query, ownerId)
	err := r.db.Select(&sessions, query, ownerId)

	return sessions, err
}

func (r *AuthPostgres) GetSessionsDetails(userId uint) ([]models.SessionItem, error) {
	var sessions []models.SessionItem
	getSessionQuery := fmt.Sprintf(`SELECT s.id, s.user_id, sh.ip_address, sh.city, sh.os, sh.time, a.name, at.type FROM %s s 
												INNER JOIN %s sh ON s.id = sh.id INNER JOIN %s a ON sh.app_id = a.id
													INNER JOIN %s at ON a.type_id = at.id
													WHERE s.user_id=$1`,
		sessionsTable, sessionsHistoryTable, applicationsTable, applicationTypesTable)
	if err := r.db.Select(&sessions, getSessionQuery, userId); err != nil {
		logrus.WithFields(logrus.Fields{
			"package":  "repository",
			"file":     "auth_postgres.go",
			"function": "GetSessionsDetails",
			"message":  err,
		}).Errorf("failed to execute query")
		return nil, err
	}

	return sessions, nil
}

func (r *AuthPostgres) GetSessionById(id uint) (models.Session, error) {
	var session models.Session

	query := fmt.Sprintf(
		"SELECT id, user_id, refresh_token, refresh_uuid, issused_at from %s WHERE id=$1", sessionsTable)

	err := r.db.Get(&session, query, id)

	return session, err
}

func (r *AuthPostgres) Logout(sessionId uint) error {
	tx, err := r.db.Begin()
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"package":  "repository",
			"file":     "auth_postgres.go",
			"function": "Logout",
			"message":  err,
		}).Errorf("error while starting transaction")
		return err
	}

	updateSessionQuery := fmt.Sprintf(`DELETE FROM %s WHERE id=$1`, sessionsTable)
	_, err = tx.Exec(updateSessionQuery, sessionId)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"package":  "repository",
			"file":     "auth_postgres.go",
			"function": "Logout",
			"message":  err,
		}).Errorf("failed to execute query")

		tx.Rollback()
		return err
	}

	return tx.Commit()
}
