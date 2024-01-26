#/bin/bash

# MEANT FOR LOCAL DEV ONLY

# Run this script to setup a new test database on an already running
# postgres container (set DB_CONTAINER_NAME below)

#### Setting up a database for local development

ARBORIST_CONTAINER_NAME="arborist"

docker exec -i \
$ARBORIST_CONTAINER_NAME \
createdb

sleep 2

docker exec -i \
$ARBORIST_CONTAINER_NAME \
./migrations/latest
