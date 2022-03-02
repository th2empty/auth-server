package models

type SessionHistoryItem struct {
	Id        int64  `json:"id" db:"id"`
	AppId     uint   `json:"app_id" db:"app_id"`
	IpAddress string `json:"ip_address" db:"ip_address"`
	City      string `json:"city" db:"city"`
	OS        string `json:"os" db:"os"`
	Time      uint64 `json:"time" db:"time"`
}
