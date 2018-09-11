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

## Setup

### Building From Source

Build the go code with:
```bash
go build -o bin/arborist
```

### Building and Running a Docker Image

Build the docker image for arborist:
```bash
# Run from root directory
docker build -t arborist .
```

Run the docker image:
```bash
docker run -p 8080:8080 arborist --port 8080
```
(This command exposes arborist on port 8080 in the docker image, and maps port
8080 from the docker image onto 8080 on the host machine.)

## Development

### Tests

Run all the tests:
```bash
go test ./...
```
