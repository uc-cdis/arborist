package arborist_test

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// blockedWait is how long to give a statement to finish before treating it as
// blocked on a lock held by the other transaction.
const blockedWait = 200 * time.Millisecond

func openTestDB(t *testing.T) *sqlx.DB {
	db, err := sqlx.Open("postgres", os.Getenv("ARBORIST_TEST_DB"))
	if err == nil {
		err = db.Ping()
	}
	if err != nil {
		t.Fatal(err)
	}
	return db
}

// countResources counts the resource at `path` and everything under it.
func countResources(t *testing.T, db *sqlx.DB, path string) int {
	var n int
	err := db.Get(&n, "SELECT COUNT(*) FROM resource WHERE path <@ text2ltree($1)", path)
	require.NoError(t, err)
	return n
}

// These tests interleave a child insert with a delete of its parent. Whichever
// order the two transactions run in, the end state must not have a child
// without its parent.
func TestResourceParentRace(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()

	t.Run("CreateThenDelete", func(t *testing.T) {
		_, err := db.Exec("INSERT INTO resource(path) VALUES ('race_a')")
		require.NoError(t, err)
		defer db.Exec("DELETE FROM resource WHERE path <@ 'race_a'")

		txCreate, err := db.Beginx()
		require.NoError(t, err)
		_, err = txCreate.Exec("INSERT INTO resource(path) VALUES ('race_a.kid')")
		require.NoError(t, err)

		deleted := make(chan error, 1)
		commitDelete := make(chan struct{}, 1)
		done := make(chan error, 1)
		go func() {
			txDelete, err := db.Beginx()
			if err != nil {
				deleted <- err
				done <- err
				return
			}
			_, err = txDelete.Exec("DELETE FROM resource WHERE path = 'race_a'")
			deleted <- err
			<-commitDelete
			if err != nil {
				_ = txDelete.Rollback()
				done <- err
				return
			}
			done <- txDelete.Commit()
		}()

		// the delete should wait for the transaction creating the child
		select {
		case err := <-deleted:
			require.NoError(t, err)
			t.Log("delete of parent did not wait for child insert")
		case <-time.After(blockedWait):
		}
		require.NoError(t, txCreate.Commit())
		commitDelete <- struct{}{}
		require.NoError(t, <-done)

		assert.Equal(t, 0, countResources(t, db, "race_a"), "deleting the parent left an orphaned child")
	})

	t.Run("DeleteThenCreate", func(t *testing.T) {
		_, err := db.Exec("INSERT INTO resource(path) VALUES ('race_b')")
		require.NoError(t, err)
		defer db.Exec("DELETE FROM resource WHERE path <@ 'race_b'")

		txDelete, err := db.Beginx()
		require.NoError(t, err)
		_, err = txDelete.Exec("DELETE FROM resource WHERE path = 'race_b'")
		require.NoError(t, err)

		created := make(chan error, 1)
		go func() {
			txCreate, err := db.Beginx()
			if err != nil {
				created <- err
				return
			}
			_, err = txCreate.Exec("INSERT INTO resource(path) VALUES ('race_b.kid')")
			if err != nil {
				_ = txCreate.Rollback()
				created <- err
				return
			}
			created <- txCreate.Commit()
		}()

		// the child insert should wait for the transaction deleting the parent
		var createErr error
		createFinished := false
		select {
		case createErr = <-created:
			createFinished = true
			t.Log("child insert did not wait for delete of parent")
		case <-time.After(blockedWait):
		}
		require.NoError(t, txDelete.Commit())
		if !createFinished {
			createErr = <-created
		}

		var pqErr *pq.Error
		if assert.True(t, errors.As(createErr, &pqErr), "creating child of deleted parent should fail, got: %v", createErr) {
			assert.Equal(t, "foreign_key_violation", string(pqErr.Code.Name()))
		}
		assert.Equal(t, 0, countResources(t, db, "race_b"), "deleting the parent left an orphaned child")
	})
}
