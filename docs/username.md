# Arborist username endpoints design

This document describes how Arborist should behave when the user is or is not known to Arborist.

## Context

Arborist always has 2 default groups:
- The "anonymous" group contains _all_ users, regardless of whether they are authenticated. This group has access to all the policies listed in the user.yaml's "anonymous_policies" list.
- The "logged-in" group contains all _authenticated_ users, regardless of whether they are known to Arborist. This group has access to all the policies listed in the user.yaml's "all_users_policies" list.

Some Arborist endpoints require a username (or a JWT to get the username from).

Services that communicate with Arborist (Windmill, Peregrine, Fence...) need the user's _complete_ list of resources, so they should receive anonymous and logged-in policies. But when Arborist receives the username as a query parameter, it doesn’t know if the user is logged in. Should it then return the logged-in policies or not?

## Rationale

The `auth/...` endpoints are part of a client-facing API. They should return everything the current user actually has access to. If a JWT is specified, we assume the user is logged in. If a username is specified, we assume we want to know what access the user has when logged in.

The `user/...` endpoints are part of an admin-facing API, so returning a 404 error when the specified user is not known better reflects the state of the database. If an admin hits the `user/{username}` endpoint to find out what permissions a user has, the assumption is that the admin wants to know what access the user has when logged in, so we should return anonymous _and_ logged-in policies.

If we need the list of anonymous or logged-in policies, we can hit the `group/{groupname}` endpoint.

## GET, POST auth/mapping and GET, POST auth/resources endpoints

> Note: The rationale described in this document is still accurate, but some of the statements below may be outdated. Check the [API documentation](https://petstore.swagger.io/?url=https://raw.githubusercontent.com/uc-cdis/arborist/master/docs/openapi.yaml#/) for the latest behavior of each endpoint.

The GET `auth/mapping` endpoint accepts a username as an optional query parameter. If the username is not specified, we try to get it from the JWT in the 'Authorization' header.
The GET `auth/resources` endpoint only passes the username in a JWT in the 'Authorization' header. 
The POST `auth/mapping` and POST `auth/resources` endpoints pass the username in the request body.

These endpoints return everything the user has access to, including anonymous and logged-in policies, following this logic:
- Username is specified and it is in Arborist's database: return user's policies + anonymous and logged-in policies.
- Username is specified but it is not in Arborist's database: return anonymous and logged-in policies.

Additionally, the GET auth/mapping and GET auth/resources endpoints have this behavior:
- No username provided (I.e., no username provided in query string, and no JWT is passed in the Authorization header): return anonymous policies only.

>Background: Originally `auth/mapping` only took the username from a query parameter. Then the revproxy needed to expose the endpoint so that Windmill could hit it. But we couldn't allow users to hit `auth/mapping` with arbitrary usernames. So the revproxy does not forward any query parameters, and we added the JWT fallback in Arborist.

## GET user/{username} and GET user/{username}/... endpoints

These endpoints have the username as a mandatory query parameter.
- Username is in Arborist's database: return user's policies + anonymous and logged-in policies.
- Username is not in Arborist's database: 404 error.
- Username is not provided: error.
