# Arborist

Arborist is the RBAC (role-based access control) policy engine for use with the
Gen3 stack.

## Overview, Terminology, and Definitions

Arborist implements RBAC based on a tree of hierarchical roles (hence the name
"arborist"), where each role has one or more sub-roles underneath it in addition
to a set of permissions.

Some definitions:

- *Permissions* are a combination of a service, an action, and some optional
  constraints.
- *Actions* are an association of a service, a resource, and a method, and
  generally correspond directly to an endpoint a user accesses.
- *Resources* are anything that should be access-controlled, uniquely
  identifiable by some name and tied to a particular service. In arborist,
  resources can have "child" resources, where access to a resource higher in the
  tree implies access to resources below it.

## Setup

Build the go code with:
```bash
go build -o bin/arborist
```

### Building and Running Docker Image

Build the docker image for arborist:
```bash
docker build -t arborist .
```

Run the docker image:
```bash
docker run -p 8080:8080 arborist --port 8080
```

## Tests

Run all the tests:
```bash
go test ./...
```
