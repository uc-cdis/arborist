See `DEVELOP.md` in the root folder for instructions on making new migration
scripts.

*NOTE*: once a migration script is merged into master it should be treated as
read-only. Do not alter previous migration scripts, only append new ones as
necessary.

### Utility Scripts

For all migration scripts it is assumed that the necessary postgres variables
are already set, for example with environment variables, like this:

```
PGHOST=localhost PGPORT=5432 PGDATABASE=arborist_test PGUSER=postgres ./migrations/latest
```

If you get any errors from postgres about not finding or connecting to the
database, then that is probably your problem.

#### `migrations/latest`

Attempt to apply all migrations sequentially until the database is at the most
recent version.

#### `migrations/current-version`

Outputs the version from the `db_version` table. Defaults to
`"0000-00-00T000000Z"` if the database is uninitialized.

#### `migrations/up`

Try to increment the database version by applying the migration most recently
following the current version (if any).

#### `migrations/down`

Revert from the current version down to the previous one. Note that if this is
run on version 0 this will drop all the tables and may cause loss of data.
