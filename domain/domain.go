package domain

import "time"

type Vulnerability struct {
	AlertID      string `json:"alert_id"`
	AWSAccountID string `json:"aws_account_id"`
	Microservice string `json:"microservice"`
	Payload      string `json:"payload"`
	Timestamp    time.Time `json:"timestamp"`
}

type AgentState struct {
	AlertID     string    `json:"alert_id"`
	Status      string    `json:"status"`
	Patch       string    `json:"patch"`
	Verified    bool      `json:"verified"`
	CreatedAt   time.Time `json:"created_at"`
	AWSAccount  string    `json:"aws_account_id"`
	ServiceName string    `json:"microservice"`
}