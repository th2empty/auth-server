package models

type SessionItem struct {
	SessionId       int    `json:"session_id" db:"id"`
	UserId          uint   `json:"user_id" db:"user_id"`
	ApplicationName string `json:"application_name" db:"name"`
	ApplicationType string `json:"application_type" db:"type"`
	IpAddress       string `json:"ip_address" db:"ip_address"`
	City            string `json:"city" db:"city"`
	OS              string `json:"os" db:"os"`
	Time            uint64 `json:"time" db:"time"`
}
