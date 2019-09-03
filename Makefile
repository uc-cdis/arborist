_default: bin/arborist
	@:  # if we have a command this silences "nothing to be done"

bin/arborist: arborist/*.go # help: run the server
	go build -o bin/arborist

test: bin/arborist db-test # help: run the tests
	go test -v ./arborist/

coverage-viz: coverage # help: generate test coverage file and run coverage visualizer
	go tool cover --html=coverage.out

coverage: test # help: generate test coverage file
	go test --coverprofile=coverage.out ./arborist/

db-test: $(which psql) # help: set up the database for testing (run automatically by `test`)
	@echo 'createdb || true'
	@createdb 2>&1 | grep -v 'already exist' || true
	./migrations/latest

up: upgrade # help: try to migrate the database to the next more recent version
upgrade:
	./migrations/up

down: downgrade # help: try to revert the database to the previous version
downgrade:
	./migrations/down

# You can add a comment following a make target starting with "# help:" to have
# `make help` include that comment in its output.
help: # help: show this help
	@echo "Makefile utilities for arborist. Note that most require you to have already"
	@echo "exported the necessary postgres variables: \`PGDATABASE\`, \`PGUSER\`, \`PGHOST\`,"
	@echo "and \`PGPORT\`. Set \`PGSSLMODE=disable\` if not using SSL. See README for details."
	@echo ""
	@echo "The default command is bin/arborist."
	@echo ""
	@grep -h "^.*:.*# help" $(MAKEFILE_LIST) | grep -v grep | sed -e "s/:.*# help:/:/"
