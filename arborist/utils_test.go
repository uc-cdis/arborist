package arborist

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestStructJSONFields(t *testing.T) {
	testStruct := struct {
		A string `json:"a"`
		B int    `json:"b"`
	}{}
	resultFields := structJSONFields(testStruct)
	expectedFields := map[string]struct{}{
		"a": struct{}{},
		"b": struct{}{},
	}
	if !reflect.DeepEqual(resultFields, expectedFields) {
		t.Logf("expected: %s", expectedFields)
		t.Logf("result: %s", resultFields)
		t.Fail()
	}
}

func TestValidateJSON(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		testStruct := struct {
			A string `json:"a"`
			B int    `json:"b"`
		}{}
		bytes := `{"a": "test", "b": 4}`
		content := make(map[string]interface{})
		json.Unmarshal(json.RawMessage(bytes), &content)
		err := validateJSON("test", testStruct, content, nil)
		if err != nil {
			t.Fatal(err.Error())
		}

		t.Run("optionalFields", func(t *testing.T) {
			testStruct := struct {
				A string `json:"a,omitempty"`
				B int    `json:"b"`
			}{}
			bytes := `{"a": "test"}`
			content := make(map[string]interface{})
			json.Unmarshal(json.RawMessage(bytes), &content)
			err := validateJSON(
				"test",
				testStruct,
				content,
				map[string]struct{}{"b": struct{}{}},
			)
			if err != nil {
				t.Fatal(err.Error())
			}
		})

		t.Run("omitempty", func(t *testing.T) {
			testStruct := struct {
				A string `json:"a,omitempty"`
				B int    `json:"b"`
			}{}
			bytes := `{"a": "test", "b": 4}`
			content := make(map[string]interface{})
			json.Unmarshal(json.RawMessage(bytes), &content)
			err := validateJSON("test", testStruct, content, nil)
			if err != nil {
				t.Fatal(err.Error())
			}
		})
	})

	t.Run("invalid", func(t *testing.T) {
		t.Run("jsonMissingField", func(t *testing.T) {
			testStruct := struct {
				A string `json:"a"`
				B int    `json:"b"`
			}{}
			bytes := `{"a": "test"}`
			content := make(map[string]interface{})
			json.Unmarshal(json.RawMessage(bytes), &content)
			err := validateJSON("test", testStruct, content, nil)
			if err == nil {
				t.Fatal("no error returned")
			}
		})

		t.Run("jsonExtraField", func(t *testing.T) {
			testStruct := struct {
				A string `json:"a"`
				B int    `json:"b"`
			}{}
			bytes := `{"a": "test", "b": 4, "c": "extraneous"}`
			content := make(map[string]interface{})
			json.Unmarshal(json.RawMessage(bytes), &content)
			err := validateJSON("test", testStruct, content, nil)
			if err == nil {
				t.Fatal("no error returned")
			}
		})
	})
}
