module github.com/uc-cdis/arborist

go 1.26.4

require (
	github.com/go-jose/go-jose/v3 v3.0.5 // can be upgraded to v4 once we use go 1.21+. see https://github.com/uc-cdis/arborist/pull/181
	github.com/gorilla/handlers v1.5.2
	github.com/gorilla/mux v1.8.1
	github.com/jmoiron/sqlx v1.4.0
	github.com/lib/pq v1.12.3
	github.com/stretchr/testify v1.11.1
	github.com/uc-cdis/go-authutils v0.1.3-0.20251210162059-6e78e9723952
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/crypto v0.53.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
