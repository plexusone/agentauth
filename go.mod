module github.com/plexusone/agentauth

go 1.26.0

require (
	github.com/aistandardsio/agent-protocols v0.6.0
	github.com/google/uuid v1.6.0
	github.com/mattn/go-sqlite3 v1.14.47
)

require github.com/golang-jwt/jwt/v5 v5.3.1 // indirect

replace github.com/aistandardsio/agent-protocols => ../../aistandardsio/agent-protocols
