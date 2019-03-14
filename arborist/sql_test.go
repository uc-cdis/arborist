package arborist

import (
	"fmt"
	"testing"
)

func TestMultiInsertStmt(t *testing.T) {
	for i := 1; i <= 10; i++ {
		t.Run(fmt.Sprintf("multiInsertStmt%d", i), func(t *testing.T) {
			_ = multiInsertStmt("test(a, b)", i)
			// TODO
		})
	}
}
