package arborist

import (
	"os"
	"sync"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMultiInsertStmt(t *testing.T) {
	t.Run("multiInsertStmt1", func(t *testing.T) {
		expected := "INSERT INTO test(a, b) VALUES ($1, $2)"
		assert.Equal(t, multiInsertStmt("test(a, b)", 1), expected)
	})
	t.Run("multiInsertStmt2", func(t *testing.T) {
		expected := "INSERT INTO test(a, b) VALUES ($1, $2), ($3, $4)"
		assert.Equal(t, multiInsertStmt("test(a, b)", 2), expected)
	})
}

func TestTransactify(t *testing.T) {
	db, err := sqlx.Open("postgres", os.Getenv("ARBORIST_TEST_DB"))
	if err == nil {
		err = db.Ping()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	deadlock := error(&pq.Error{Code: "40P01"})

	t.Run("RetriesTransientError", func(t *testing.T) {
		attempts := 0
		errResponse := transactify(db, func(tx *sqlx.Tx) *ErrorResponse {
			attempts++
			if attempts < maxTransactionAttempts {
				return newErrorResponse("deadlock", 400, &deadlock)
			}
			return nil
		})
		assert.Nil(t, errResponse)
		assert.Equal(t, maxTransactionAttempts, attempts)
	})

	t.Run("GivesUpWith503", func(t *testing.T) {
		attempts := 0
		errResponse := transactify(db, func(tx *sqlx.Tx) *ErrorResponse {
			attempts++
			return newErrorResponse("deadlock", 400, &deadlock)
		})
		require.NotNil(t, errResponse)
		assert.Equal(t, 503, errResponse.HTTPError.Code)
		assert.Equal(t, maxTransactionAttempts, attempts)
	})

	t.Run("DoesNotRetryOtherErrors", func(t *testing.T) {
		attempts := 0
		missingParent := error(&pq.Error{Code: "23503"})
		errResponse := transactify(db, func(tx *sqlx.Tx) *ErrorResponse {
			attempts++
			return newErrorResponse("missing parent", 400, &missingParent)
		})
		require.NotNil(t, errResponse)
		assert.Equal(t, 400, errResponse.HTTPError.Code)
		assert.Equal(t, 1, attempts)
	})

	// Two transactions lock the same two rows in opposite orders. Postgres
	// aborts one of them (after `deadlock_timeout`, 1s by default); transactify
	// should retry it so both succeed.
	t.Run("RecoversFromRealDeadlock", func(t *testing.T) {
		_, err := db.Exec("INSERT INTO resource(path) VALUES ('deadlock_a'), ('deadlock_b')")
		require.NoError(t, err)
		defer db.Exec("DELETE FROM resource WHERE path IN ('deadlock_a', 'deadlock_b')")

		var bothLocked sync.WaitGroup
		bothLocked.Add(2)
		lock := func(tx *sqlx.Tx, path string) *ErrorResponse {
			_, err := tx.Exec("SELECT 1 FROM resource WHERE path = text2ltree($1) FOR UPDATE", path)
			if err != nil {
				return newErrorResponse(err.Error(), 500, &err)
			}
			return nil
		}
		lockInOrder := func(first, second string, attempts *int) func(tx *sqlx.Tx) *ErrorResponse {
			return func(tx *sqlx.Tx) *ErrorResponse {
				*attempts++
				if errResponse := lock(tx, first); errResponse != nil {
					return errResponse
				}
				if *attempts == 1 {
					bothLocked.Done()
					bothLocked.Wait()
				}
				return lock(tx, second)
			}
		}

		var attemptsAB, attemptsBA int
		var errAB, errBA *ErrorResponse
		var done sync.WaitGroup
		done.Add(2)
		go func() {
			defer done.Done()
			errAB = transactify(db, lockInOrder("deadlock_a", "deadlock_b", &attemptsAB))
		}()
		go func() {
			defer done.Done()
			errBA = transactify(db, lockInOrder("deadlock_b", "deadlock_a", &attemptsBA))
		}()
		done.Wait()

		assert.Nil(t, errAB)
		assert.Nil(t, errBA)
		assert.Equal(t, 3, attemptsAB+attemptsBA, "exactly one transaction should have been retried")
	})
}
