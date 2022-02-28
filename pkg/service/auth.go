package service

import (
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/spf13/viper"
	"github.com/th2empty/auth_service/configs"
	"github.com/th2empty/auth_service/pkg/models"
	"github.com/th2empty/auth_service/pkg/repository"
	"github.com/th2empty/auth_service/pkg/utils"
	"time"
)

var (
	_ = configs.InitConfig()

	issuer   = viper.GetString("auth.issuer")
	audience = viper.GetString("auth.audience")
	//salt            = viper.GetString("auth.salt")
	accessTokenTTL  = viper.GetDuration("auth.access_token_ttl") * time.Minute
	refreshTokenTTL = viper.GetDuration("auth.refresh_token_ttl") * time.Hour
	signingKey      = viper.GetString("auth.signing_key")
)

type AccessTokenClaims struct {
	jwt.StandardClaims
	UserId    uint   `json:"user_id"`
	Username  string `json:"username"`
	RoleId    uint   `json:"role_id"`
	SessionId uint   `json:"session_id"`
}

type RefreshTokenClaims struct {
	jwt.StandardClaims
	UserId      uint   `json:"user_id"`
	Username    string `json:"username"`
	RoleId      uint   `json:"role_id"`
	SessionID   uint   `json:"session_id"`
	RefreshUUID string `json:"refresh_uuid"`
}

type AuthService struct {
	repo repository.Authorization
}

func NewAuthService(repo repository.Authorization) *AuthService {
	return &AuthService{repo: repo}
}

func (s *AuthService) CreateUser(user models.User) (int, error) {
	user.Password = utils.GeneratePasswordHash(user.Password)
	return s.repo.CreateUser(user)
}

func (s *AuthService) GetUser(username, password string) (models.User, error) {
	return s.repo.GetUser(username, password)
}

func (s *AuthService) GetUserById(id uint) (models.User, error) {
	return s.repo.GetUserById(id)
}

func (s *AuthService) GetSessions(ownerId uint) ([]models.Session, error) {
	return s.repo.GetSessions(ownerId)
}

func (s *AuthService) GetSessionById(id uint) (models.Session, error) {
	return s.repo.GetSessionById(id)
}

func (s *AuthService) AddSession(session models.Session) (uint, error) {
	return s.repo.AddSession(session)
}

func (s *AuthService) UpdateSession(session models.Session) error {
	return s.repo.UpdateSession(session)
}

func (s *AuthService) GenerateTokens(user models.User, session models.Session) ([]string, error) {
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, &AccessTokenClaims{
		jwt.StandardClaims{
			Issuer:    issuer,
			Audience:  audience,
			ExpiresAt: time.Now().Add(accessTokenTTL).Unix(),
			IssuedAt:  time.Now().Unix(), // Token generation time
			Id:        uuid.New().String(),
		},
		user.Id, user.Username, user.RoleId, session.SessionId,
	})

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, &RefreshTokenClaims{
		jwt.StandardClaims{
			Issuer:    issuer,
			Audience:  audience,
			ExpiresAt: time.Now().Add(refreshTokenTTL).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
		user.Id, user.Username, user.RoleId,
		session.SessionId, session.RefreshUUID,
	})

	sAccessToken, err := accessToken.SignedString([]byte(signingKey))
	if err != nil {
		return nil, err
	}
	sRefreshToken, err := refreshToken.SignedString([]byte(signingKey))

	return []string{sAccessToken, sRefreshToken}, err
}

func (s *AuthService) ParseAccessToken(inputToken string) (*AccessTokenClaims, error) {
	token, err := jwt.ParseWithClaims(inputToken, &AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("invalid signing method")
		}

		return []byte(signingKey), nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*AccessTokenClaims)
	if !ok {
		return nil, errors.New("token claims are not of type *tokenClaims")
	}

	return claims, nil
}

func (s *AuthService) ParseRefreshToken(inputToken string) (*RefreshTokenClaims, error) {
	token, err := jwt.ParseWithClaims(inputToken, &RefreshTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("invalid signing method")
		}

		return []byte(signingKey), nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*RefreshTokenClaims)
	if !ok {
		return nil, errors.New("token claims are not of type *tokenClaims")
	}

	return claims, nil
}

func (s *AuthService) Logout(sessionId uint) error {
	return s.repo.Logout(sessionId)
}
