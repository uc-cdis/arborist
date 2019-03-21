### SQL

[This page](http://jmoiron.github.io/sqlx/) is a useful overview of `sqlx`
usage, the package which arborist uses for the database interface.

Be careful with `sql.DB` transactions; namely, be sure to close them if
returning early because of errors or similar, otherwise the transaction holds
its connection open. Similarly, when working with some `sql.Rows` always call
`.Close()` so the open connection is returned to the pool.

Go's SQL package handles the connection pool implicitly, though the size of the
pool is configurable. See [here](http://jmoiron.github.io/sqlx/#connectionPool)
for a bit more detail.

#### Migration Scripts

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

### Testing

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
