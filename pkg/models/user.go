package models

type User struct {
	Id       uint   `json:"-" db:"id"`
	Username string `json:"username" binding:"required" db:"username"`
	Email    string `json:"email" db:"email"`
	Password string `json:"password" binding:"required" db:"password_hash"`
	AvatarId uint   `json:"avatar_id" db:"avatar_id"`
	RoleId   uint   `json:"role_id" db:"role_id"`
}
