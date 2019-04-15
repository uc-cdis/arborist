# Development

## Quickstart

### Adding or Modifying Endpoints

Here's a quick overview for the typical process to go through to alter or add
some functionality for the server:

- Start with `server.go`. The `MakeRouter` function is where all the endpoints
  are defined. All the handler functions are methods on the server so we can
  pass in the database reference and the logger as necessary.
    - If adding a new endpoint, add it in `MakeRouter`, and make a new handler
      function; you can look at the existing ones for examples.
    - If changing an existing endpoint then look up the handler function set to
      handle the endpoint in question.
- In a handler function, you probably want to interact with the database
  somehow. Put the database function in whatever file is mostly closely related
  (e.g. `listUsersFromDb` goes in `users.go`), and call it in the handler
  function, passing in `server.db`. For almost all the models there is one
  version which works with JSON, and one which is how entries are retrieved from
  the database; the latter are named in the pattern of `xFromQuery`.
- Do whatever logic on the database results.
- Ultimately for an endpoint returning a response we want to put together
  something which can be marshalled into JSON. Take that and do a call like
  this:

```go
_ = jsonResponseFrom(result, http.StatusOK).write(w, r)
```

That's it!

### Structs

As mentioned in the previous section, for most models used in arborist there's a
pattern of having two structs to handle it, one with JSON tags and another which
can accept a database query. The query one, named with a `FromQuery` suffix by
convention, should have a `standardize()` method which converts it to the JSON
version. Take the `User` structs as an example (at the time of writing):

```go
type User struct {
    Name     string   `json:"name"`
    Email    string   `json:"email,omitempty"`
    Groups   []string `json:"groups"`
    Policies []string `json:"policies"`
}

type UserFromQuery struct {
    Name     string         `db:"name"`
    Email    *string        `db:"email"`
    Groups   pq.StringArray `db:"groups"`
    Policies pq.StringArray `db:"policies"`
}

func (userFromQuery *UserFromQuery) standardize() User {
    user := User{
        Name:     userFromQuery.Name,
        Groups:   userFromQuery.Groups,
        Policies: userFromQuery.Policies,
    }
    if userFromQuery.Email != nil {
        user.Email = *userFromQuery.Email
    }
    return user
}
```

The `UserFromQuery` struct is used for database operations:
```go
users := []UserFromQuery{}
err := db.Select(&users, stmt)
```
and the `User` one for returning JSON responses (where typically we got the
`User` struct from calling `standardize()` on the `UserFromQuery` version):
```
userFromQuery, err := userWithName(server.db, username)
user := userFromQuery.standardize()
_ = jsonResponseFrom(user, http.StatusOK).write(w, r)
```

### Modifying Database Schema

See the SQL section and read through all the explanation on the migration
scripts. We've taken the approach of using raw SQL plus some utility wrappers
instead of an ORM so changes may need to be made to the queries on some
endpoints.

## SQL

[This page](http://jmoiron.github.io/sqlx/) is a useful overview of `sqlx`
usage, the package which arborist uses for the database interface.

Be careful with `sql.DB` transactions; namely, be sure to close them if
returning early because of errors or similar, otherwise the transaction holds
its connection open. Similarly, when working with some `sql.Rows` always call
`.Close()` so the open connection is returned to the pool.

Go's SQL package handles the connection pool implicitly, though the size of the
pool is configurable. See [here](http://jmoiron.github.io/sqlx/#connectionPool)
for a bit more detail.

### Migration Scripts

Reference previous `migrations` for examples on how to write migration scripts
correctly. The crucial points are

- Create a subdirectory in `migrations` named in the format
  `{YYYY}-{MM}-{DD}T{HH}{MM}{SS}Z_{name}`, which is the ISO date format
  followed optionally by a human-readable name describing the migration.
- This subdirectory must contain an `up.sql` and a `down.sql` which apply and
  revert the migration, respectively.
- The `up.sql` script must *update* the singular row of `db_version` to
  increment the integer version ID, and change the `version` text column to
  reflect the exact folder name.

Test a migration by applying `up.sql` and `down.sql` sequentially to ensure
both work as expected.

## Testing

For testing an HTTP server, we use the `httptest` module to "record" requests
that we send to the handler for our server. The `httptest.ResponseRecorder`
stores the response information including `.Code` and `.Body` which can be
returned as a string or bytes.

This is a basic pattern for a test to hit a server endpoint (in this example,
sending some JSON in a `POST`):

```go
// arborist-specific
server := arborist.NewServer()
// ^ more setup for database, etc
logBuffer := bytes.NewBuffer([]byte{})
handler := server.MakeRouter(logBuffer)
// dump logBuffer to see server logs, if an error happens

// generic
w := httptest.NewRecorder()
req := newRequest("POST", "/some/endpoint", nil)
handler.ServeHTTP(w, req)
```

At this point we can inspect the recorder `w` for what we care about in the
response. Suppose we expect to get some JSON in the response from this request.
Our test would look something like this (here, we use the `testify/assert`
package for convenience):

```go
// one-off inline struct to read the response into
result := struct {
    A string `json:"a"`
    B int    `json:"b"`
}{}
// Try to read response bytes into result JSON.
err := json.Unmarshal(w.Body.Bytes(), &result)
if err != nil {
    t.Error("failed to read JSON")
}
assert.Equal(t, "what we expect", result.A, "result had the wrong value for a")
```

### Code Coverage

Run this to both generate a coverage output file usable by go tools,
`coverage.out`, and open it using the go coverage tool to visualize line-by-line
coverage.
```
make coverage-viz
```
