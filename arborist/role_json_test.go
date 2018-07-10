package arborist

import (
	"encoding/json"
	"testing"
)

func TestRoleToJSON(t *testing.T) {
	role := exampleRole()
	roleJSON := role.toJSON()
	bytes, err := json.Marshal(roleJSON)
	if err != nil {
		t.Fatal(err.Error())
	}

	check := func(result string, expected string) {
		if result != expected {
			t.Logf("expected: %s", expected)
			t.Logf("result: %s", result)
			t.Fail()
		}
	}

	check(string(bytes), string(bytes))
	// TODO
}
