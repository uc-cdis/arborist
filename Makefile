GOYACC ?= goyacc

_default: bin/arborist

test: bin/arborist db-test
	go test -v ./.../

bin/arborist: arborist/*.go
	go build -o bin/arborist

up: upgrade
upgrade:
	./migrations/up

down: downgrade
downgrade:
	./migrations/down

db-test: $(which psql)
	-@ psql -c "CREATE DATABASE arborist_test" 2>&1 || true
	./migrations/latest

arborist/resource_rules.go: arborist/resource_rules.y
	$(GOYACC) -o arborist/resource_rules.go arborist/resource_rules.y
