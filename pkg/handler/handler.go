package handler

import (
	"github.com/gin-gonic/gin"
	"github.com/swaggo/files"
	"github.com/swaggo/gin-swagger"
	"github.com/th2empty/auth_service/pkg/service"

	_ "github.com/th2empty/auth_service/docs"
)

type Handler struct {
	services *service.Service
}

func NewHandler(services *service.Service) *Handler {
	return &Handler{services: services}
}

func (h *Handler) InitRoutes() *gin.Engine {
	router := gin.New()

	auth := router.Group("/auth")
	{
		auth.POST("/sign-up", h.SignUp)
		auth.POST("/sign-in", h.SignIn)
		auth.POST("/identity", h.userIdentity)
		auth.POST("/refresh-token", h.RefreshToken)
	}

	account := router.Group("/account", h.userIdentity)
	{
		account.GET("/sessions", h.GetSessionsDetails)
		account.POST("/logout", h.Logout)
	}

	router.GET("/docs/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	return router
}
