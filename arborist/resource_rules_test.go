package arborist

import (
	"fmt"
	"testing"
)

func ParseOrFail(t *testing.T, exp string, vars map[string]interface{}) bool {
	rv, err := Parse(exp, vars)
	if err != nil {
		t.Error(err)
	}
	return rv
}

func assertEqual(t *testing.T, a interface{}, b interface{}, message string) {
	if a == b {
		return
	}
	if len(message) == 0 {
		message = fmt.Sprintf("%v != %v", a, b)
	}
	t.Fatal(message)
}

func TestParse(t *testing.T) {
	vars := map[string]interface{}{
		"T": true,
		"F": false,
	}

	assertEqual(t, ParseOrFail(t, "not T", vars), false, "")
	assertEqual(t, ParseOrFail(t, "not F", vars), true, "")
	assertEqual(t, ParseOrFail(t, "not not T", vars), true, "")
	assertEqual(t, ParseOrFail(t, "not not F", vars), false, "")

	assertEqual(t, ParseOrFail(t, "T and T", vars), true, "")
	assertEqual(t, ParseOrFail(t, "T and F", vars), false, "")
	assertEqual(t, ParseOrFail(t, "F and T", vars), false, "")
	assertEqual(t, ParseOrFail(t, "F and F", vars), false, "")

	assertEqual(t, ParseOrFail(t, "T or T", vars), true, "")
	assertEqual(t, ParseOrFail(t, "T or F", vars), true, "")
	assertEqual(t, ParseOrFail(t, "F or T", vars), true, "")
	assertEqual(t, ParseOrFail(t, "F or F", vars), false, "")

	assertEqual(t, ParseOrFail(t, "not  T or T", vars), true, "")
	assertEqual(t, ParseOrFail(t, "not (T or T)", vars), false, "")
	assertEqual(t, ParseOrFail(t, "not  T and F", vars), false, "")
	assertEqual(t, ParseOrFail(t, "not (T and F)", vars), true, "")
}
