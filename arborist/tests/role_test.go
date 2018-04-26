package tests

import (
	"encoding/json"
	"testing"

	"github.com/uc-cdis/arborist/arborist"
	"github.com/uc-cdis/arborist/arborist/tests/cases"
)

func TestUnmarshalRole(t *testing.T) {
	var role *arborist.Role = &arborist.Role{}
	err := json.Unmarshal([]byte(cases.EXAMPLE_ROLE), role)
	if err != nil {
		t.Fatalf("%s", err)
	}
}
