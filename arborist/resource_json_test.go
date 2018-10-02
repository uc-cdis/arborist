package arborist

import (
	"encoding/json"
	"testing"
)

func TestToJSON(t *testing.T) {
	check := func(expected string, result string) {
		if result != expected {
			t.Log("incorrect JSON serialization of resource")
			t.Logf("expected: %s", expected)
			t.Logf("result: %s", result)
			t.Fail()
		}
	}

	root := resource("root", "", nil, nil)
	bytes, err := json.Marshal(root.toJSON())
	if err != nil {
		panic(err)
	}
	// Fields in the JSON are in the order defined in the struct.
	expected := ("{" +
		"\"name\":\"root\"," +
		"\"path\":\"/\"," +
		"\"description\":\"\"," +
		"\"subresources\":[]" +
		"}")
	result := string(bytes)
	check(expected, result)

	subnode_0 := resource("foo", "subnode under root", root, nil)
	bytes, err = json.Marshal(subnode_0.toJSON())
	if err != nil {
		panic(err)
	}
	// Fields in the JSON are in the order defined in the struct.
	expected_subnode_0 := ("{" +
		"\"name\":\"foo\"," +
		"\"path\":\"/foo\"," +
		"\"description\":\"subnode under root\"," +
		"\"subresources\":[]" +
		"}")
	result = string(bytes)
	check(expected_subnode_0, result)

	// Check root node again now that there's a subnode.
	bytes, err = json.Marshal(root.toJSON())
	if err != nil {
		panic(err)
	}
	// Fields in the JSON are in the order defined in the struct.
	expected = ("{" +
		"\"name\":\"root\"," +
		"\"path\":\"/\"," +
		"\"description\":\"\"," +
		"\"subresources\":[" +
		expected_subnode_0 +
		"]" +
		"}")
	result = string(bytes)
	check(expected, result)
}
