package arborist

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
