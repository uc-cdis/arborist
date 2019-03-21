_default: bin/arborist

test: bin/arborist db-test
	go test -v ./.../

bin/arborist:
	go build -o bin/arborist

up: upgrade
upgrade:
	psql

down: downgrade
downgrade:
	psql

revision:
	REV = migrations/`date -u +"%Y-%m-%dT%H:%M:%SZ"`

db-test: $(which psql)
	-@ psql -c "CREATE DATABASE arborist_test" 2>&1 || true
	./migrations/latest
