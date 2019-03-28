# Arborist

Arborist a role-based access control (RBAC) policy engine, designed for use with
the [Gen3 stack](https://gen3.org/). Arborist tracks resources requiring access
control, along with actions which users may perform to operate on these
resources, and roles, which aggregate permissions to perform one or more
actions. Finally, policies tie together a set of resources with a set of roles;
when granted to a user, a policy grants authorization to act as one of the roles
over one of the resources. Resources are arranged hierarchically like a
filesystem, and access to one resource implies access to its subresources.

For example, a simple policy might grant a role `metadata-submitter` on the
resource `/projects/project-abc`. Now users which are granted this policy can
perform the actions that being a `metadata-submitter` entails, for all resources
under `project-abc`.

In the Gen3 stack, arborist is integrated closely with fence. Fence acts as the
central identify provider, issuing user tokens (in the form of JWTs) containing
the list of policies in the arborist model which are granted to that user. Other
microservices needing to check user authorization to operate on a resource can
statelessly verify the user's authorization, making a request to arborist with
the user's JWT and receiving a response for the authorization decision.

## Setup

### Quickstart

You will need these:

- [Go](https://golang.org/dl/)
- [PostgreSQL](https://www.postgresql.org/download/)

```bash
go get -u github.com/uc-cdis/arborist
make
psql
export PGDATABASE=arborist_test PGUSER=username PGHOST=localhost PGPORT=5432 PGSSLMODE=disable
# export any other PG variables as necessary
./migrations/latest
```

### Building From GitHub

Clone/Build/Install all-in-one command:

```bash
go get -u github.com/uc-cdis/arborist
```

The cloned source code can be found under `$GOPATH`, usually `~/go/` if not set.
In the source folder, you can run `go install` to rebuild the project. The
executable can be found under `$GOPATH/bin/`, which you may want to add to your
`$PATH` if not done yet.

### Building From Source

If you have already checked out the repository locally, you can build the
executable from there directly, which will include any local changes during
development.

Running `make` will build the code:
```bash
make
```

Be aware that the source code must have been
[cloned correctly](https://github.com/golang/go/wiki/GitHubCodeLayout) into
`$GOPATH`, see also the previous section. `go build` will not work correctly if
you cloned the repository outside of the location that `go` expects. One option
to work around this, if you prefer to work with the code elsewhere in the
filesystem, is to create a symlink from the desired location to wherever the
repository lives under `$GOPATH`.

## Overview, Terminology, and Definitions

We will start from the lowest-level definitions, and work upwards.

- *Action:* a method (identified by a string) on a service (also identified by
  string) and generally correspond directly to an endpoint or simple operation
  done through the given service. An example might be something like this:
```
{
    "service": "fence",
    "method": "presigned-url-download",
}
```
- *Permission:* a combination of an action, and some optional constraints
  (key-value pairs which restrict the context of the action).
- *Role:* collections of permissions. Roles are uniquely identified by an ID
  field.
- *Resources* are anything that should be access-controlled, organized like
  directories of a filesystem. Resources are uniquely identifiable by their full
  path. Resources can have "child" resources (subdirectories, or
  sub-subdirectories etc., in the filesystem model), where access to one
  resource implies access to all the resources below it. A resource might be,
  for example, an entire project in a data commons, like
  `/projects/project-abc`.

## Development

### Tests

Run all the tests:
```bash
go test ./...
```
