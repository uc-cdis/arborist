package tests

import (
	"encoding/json"
	"testing"

	"github.com/uc-cdis/arborist/arborist"
	"github.com/uc-cdis/arborist/arborist/tests/cases"
)

func TestMarshalRole(t *testing.T) {
}

func TestUnmarshalRole(t *testing.T) {
	var role *arborist.Role = &arborist.Role{}
	err := json.Unmarshal([]byte(cases.RoleChefDePartieJSON), role)
	if err != nil {
		t.Fatalf("%s", err)
	}
}
