package handler

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/th2empty/auth_service/pkg/models"
	"github.com/th2empty/auth_service/pkg/utils"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type signUpInput struct {
	Email    string `json:"email"`
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// @Summary SignUp
// @Tags auth
// @Description Create account
// @ID create-account
// @Accept json
// @Produce json
// @Param input body signUpInput true "account info"
// @Success 200 {integer} integer 1
// @Failure 400 {object} errorResponse
// @Failure 500 {object} errorResponse
// @Router /auth/sign-up [post]
func (h *Handler) SignUp(ctx *gin.Context) {
	var input models.User

	if err := ctx.BindJSON(&input); err != nil {
		newErrorResponse(ctx, http.StatusBadRequest, err.Error())
		return
	}

	id, err := h.services.Authorization.CreateUser(input)
	if err != nil {
		newErrorResponse(ctx, http.StatusInternalServerError, err.Error())
		return
	}

	ctx.JSON(http.StatusOK, map[string]interface{}{
		"id": id,
	})
}

type signInInput struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// @Summary SignIn
// @Tags auth
// @Description login
// @ID login
// @Accept json
// @Produce json
// @Param app_id header integer true "application id"
// @Param os_name header string true "Operating system name"
// @Param input body signInInput true "account info"
// @Success 200 {integer} integer 1
// @Failure 400 {object} errorResponse
// @Failure 500 {object} errorResponse
// @Router /auth/sign-in [post]
func (h *Handler) SignIn(ctx *gin.Context) {
	var input signInInput

	if err := ctx.BindJSON(&input); err != nil {
		newErrorResponse(ctx, http.StatusBadRequest, err.Error())
		return
	}

	user, err := h.services.GetUser(input.Username, utils.GeneratePasswordHash(input.Password))
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"package":  "handler",
			"file":     "auth.go",
			"function": "SignIn",
			"message":  err,
		}).Errorf("scan scopies returned error")
		newErrorResponse(ctx, http.StatusInternalServerError, err.Error())
		return
	}
	sessions, err := h.services.GetSessions(user.Id)
	newSession := models.Session{
		UserId:      user.Id,
		IssusedAt:   uint64(time.Now().Unix()),
		RefreshUUID: uuid.New().String(),
	}
	if len(sessions) != 0 {
		newSession.SessionId = sessions[len(sessions)-1].SessionId + 1
	} else {
		newSession.SessionId = 1
	}

	tokens, err := h.services.Authorization.GenerateTokens(user, newSession)
	if err != nil {
		newErrorResponse(ctx, http.StatusInternalServerError, err.Error())
		return
	}

	newSession.RefreshToken = tokens[1]
	appId, err := strconv.Atoi(ctx.GetHeader("app_id"))
	if err != nil {
		appId = 1
	}
	osName := ctx.GetHeader("os_name")
	if len(osName) == 0 {
		osName = "unknown"
	}
	newSessionHistoryItem := models.SessionHistoryItem{
		IpAddress: strings.Split(ctx.Request.RemoteAddr, ":")[0],
		OS:        osName,
		City:      "unknown",
		AppId:     uint(appId),
		Time:      uint64(time.Now().Unix()),
	}

	_, err = h.services.AddSession(newSession, newSessionHistoryItem)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"package":  "handler",
			"file":     "auth.go",
			"function": "SignIn",
			"message":  err,
		}).Errorf("error while creating session")
		newErrorResponse(ctx, http.StatusInternalServerError, err.Error())
		return
	}

	ctx.JSON(http.StatusOK, map[string]interface{}{
		"access_token":  tokens[0],
		"refresh_token": tokens[1],
	})
}

// @Summary GetSessionsList
// @Security ApiKeyAuth
// @Tags account
// @Description sessions list
// @ID sessions
// @Accept json
// @Produce json
// @Success 200 {object} []models.SessionItem
// @Failure 401 {object} errorResponse
// @Failure 500 {object} errorResponse
// @Router /account/sessions [get]
func (h *Handler) GetSessionsDetails(ctx *gin.Context) {
	header := ctx.GetHeader(authorizationHeader)
	if header == "" {
		newErrorResponse(ctx, http.StatusUnauthorized, "auth header is empty")
		return
	}

	headerParts := strings.Split(header, " ")
	if len(headerParts) != 2 {
		newErrorResponse(ctx, http.StatusUnauthorized, "invalid auth header")
		return
	}

	claims, err := h.services.Authorization.ParseAccessToken(headerParts[1])
	if err != nil {
		newErrorResponse(ctx, http.StatusUnauthorized, err.Error())
		return
	}

	id := claims.UserId
	sessions, err := h.services.GetSessionsDetails(id)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"package":  "handler",
			"file":     "auth.go",
			"function": "GetSessionsDetails",
			"message":  err,
		}).Errorf("error when getting sessions")
		newErrorResponse(ctx, http.StatusInternalServerError, err.Error())
		return
	}

	ctx.JSON(http.StatusOK, sessions)
}

// @Summary Logout
// @Security ApiKeyAuth
// @Tags auth
// @Description logout
// @ID logout
// @Accept json
// @Produce json
// @Success 200 {object} map[string]string
// @Failure 401 {object} errorResponse
// @Failure 500 {object} errorResponse
// @Router /auth/logout [post]
func (h *Handler) Logout(ctx *gin.Context) {
	header := ctx.GetHeader(authorizationHeader)
	if header == "" {
		newErrorResponse(ctx, http.StatusUnauthorized, "auth header is empty")
		return
	}

	headerParts := strings.Split(header, " ")
	if len(headerParts) != 2 {
		newErrorResponse(ctx, http.StatusUnauthorized, "invalid auth header")
		return
	}

	claims, err := h.services.Authorization.ParseAccessToken(headerParts[1])
	if err != nil {
		newErrorResponse(ctx, http.StatusUnauthorized, err.Error())
		return
	}

	err = h.services.Logout(claims.SessionId)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"package":  "handler",
			"file":     "auth.go",
			"function": "Logout",
			"message":  err,
		}).Errorf("failed to logout")
		newErrorResponse(ctx, http.StatusInternalServerError, err.Error())
		return
	}

	ctx.JSON(http.StatusOK, map[string]string{
		"message": "you are logged out",
	})
}

type RefreshResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// @Summary Refresh token
// @Security RefreshApiKey
// @Tags auth
// @Description Refresh access token. The refresh-token must be passed in the header
// @ID refresh-token
// @Accept json
// @Produce json
// @Success 200 {object} RefreshResponse
// @Failure 401 {object} errorResponse
// @Failure 500 {object} errorResponse
// @Router /auth/refresh-token [post]
func (h *Handler) RefreshToken(ctx *gin.Context) {
	header := ctx.GetHeader(authorizationHeader)
	if header == "" {
		newErrorResponse(ctx, http.StatusUnauthorized, "auth header is empty")
		return
	}

	headerParts := strings.Split(header, " ")
	if len(headerParts) != 2 {
		newErrorResponse(ctx, http.StatusUnauthorized, "invalid auth header")
		return
	}

	claims, err := h.services.Authorization.ParseRefreshToken(headerParts[1])
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"package":  "handler",
			"file":     "auth.go",
			"function": "RefreshToken",
			"message":  err,
		}).Errorf("error while parsing token")
		newErrorResponse(ctx, http.StatusUnauthorized, err.Error())
		return
	}

	user, err := h.services.Authorization.GetUserById(claims.UserId)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"package":  "handler",
			"file":     "auth.go",
			"function": "RefreshToken",
			"message":  err,
		}).Errorf("error getting user id")
		newErrorResponse(ctx, http.StatusInternalServerError, err.Error())
		return
	}

	session, err := h.services.GetSessionById(claims.SessionID)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"package":  "handler",
			"file":     "auth.go",
			"function": "RefreshToken",
			"message":  err,
		}).Errorf("error while getting session by id")
		newErrorResponse(ctx, http.StatusUnauthorized, "session not found")
		return
	}

	if session.RefreshUUID != claims.RefreshUUID {
		newErrorResponse(ctx, http.StatusUnauthorized, "token ids do not match")
		return
	}

	session.RefreshUUID = uuid.New().String()

	tokens, err := h.services.Authorization.GenerateTokens(user, session)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"package":  "handler",
			"file":     "auth.go",
			"function": "RefreshToken",
			"message":  err,
		}).Errorf("error when generating a new batch of tokens")
		newErrorResponse(ctx, http.StatusInternalServerError, err.Error())
		return
	}

	session.RefreshToken = tokens[1]
	err = h.services.UpdateSession(session)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"package":  "handler",
			"file":     "auth.go",
			"function": "RefreshToken",
			"message":  err,
		}).Errorf("error when updating session")
		newErrorResponse(ctx, http.StatusInternalServerError, err.Error())
		return
	}

	ctx.JSON(http.StatusOK, map[string]interface{}{
		"access_token":  tokens[0],
		"refresh_token": tokens[1],
	})
}
