module github.com/uc-cdis/arborist

go 1.17

require (
	github.com/go-jose/go-jose/v3 v3.0.4 // can be upgraded to v4 once we use go 1.21+. see https://github.com/uc-cdis/arborist/pull/181
	github.com/gorilla/handlers v1.5.1
	github.com/gorilla/mux v1.8.0
	github.com/jmoiron/sqlx v1.3.4
	github.com/lib/pq v1.10.3
	github.com/stretchr/testify v1.8.2
	github.com/uc-cdis/go-authutils v0.1.3-0.20251210162059-6e78e9723952
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/felixge/httpsnoop v1.0.2 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/crypto v0.39.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
