package models

type Session struct {
	SessionId    uint   `json:"session_id" db:"id"`
	UserId       uint   `json:"user_id" db:"user_id"`
	RefreshToken string `json:"refresh_token" db:"refresh_token"`
	RefreshUUID  string `json:"refresh_uuid" db:"refresh_uuid"`
	IssusedAt    uint64 `json:"issused_at" db:"issused_at"`
}
