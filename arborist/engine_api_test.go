package arborist

import (
	"errors"
	"testing"
)

func TestResponseErrors(t *testing.T) {
	// Test that errors in the response serialize correctly.
	t.Run("addErrorJSON", func(t *testing.T) {
		err := errors.New("example")
		response := Response{InternalError: err}
		response.Code = 500
		response.addErrorJSON()
		result := string(response.Bytes)
		expected := `{"error":{"message":"example","code":500}}`
		if result != expected {
			t.Logf("result: %s", result)
			t.Logf("expected: %s", expected)
			t.Fail()
		}

		err = errors.New("user error")
		response = Response{ExternalError: err}
		response.Code = 400
		response.addErrorJSON()
		result = string(response.Bytes)
		expected = `{"error":{"message":"user error","code":400}}`
		if result != expected {
			t.Logf("result: %s", result)
			t.Logf("expected: %s", expected)
			t.Fail()
		}
	})
}
