package arborist_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"

	"github.com/uc-cdis/arborist/arborist"
	"github.com/uc-cdis/go-authutils/authutils"
)

func TestServer(t *testing.T) {
	logBuffer := bytes.NewBuffer([]byte{})
	logFlags := log.Ldate | log.Ltime | log.Llongfile
	logger := log.New(logBuffer, "", logFlags)
	jwtApp := authutils.NewJWTApplication("/jwks")
	dbUrl := os.Getenv("ARBORIST_TEST_DB")
	db, err := sqlx.Open("postgres", dbUrl)
	if err != nil {
		t.Fatal(err)
	}
	server, err := arborist.
		NewServer().
		WithLogger(logger).
		WithJWTApp(jwtApp).
		WithDB(db).
		Init()
	if err != nil {
		t.Fatal(err)
	}
	handler := server.MakeRouter(logBuffer)

	// httpError is a utility function which writes some useful output after an error.
	httpError := func(t *testing.T, w *httptest.ResponseRecorder, msg string) {
		t.Errorf("%s; got status %d, response: %s", msg, w.Code, w.Body.String())
		_, err = logBuffer.WriteTo(os.Stdout)
		if err != nil {
			t.Fatal(err)
		}
	}

	// request is a utility function which wraps creating new http requests so
	// we can ignore the errors wherever this is called.
	newRequest := func(method string, url string, body io.Reader) *http.Request {
		req, err := http.NewRequest(method, url, body)
		if err != nil {
			t.Fatal(err)
		}
		return req
	}

	// testSetup should be used for any setup or teardown that should go in all
	// the tests. Use like this:
	//
	//     defer testSetup(t)
	//
	// `testSetup(t)` returns the teardown function, which when passed to defer
	// will run the teardown code at the end of the function.
	testSetup := func(t *testing.T) func(t *testing.T) {
		// ADD TEST SETUP HERE

		tearDown := func(t *testing.T) {
			// ADD TEST TEARDOWN HERE

			// clear the logs currently stored in the buffer
			logBuffer.Reset()
		}

		return tearDown
	}

	// TODO: reset database before testing

	// NOTE: in general in the test runs at this level, test results depend on
	// the previous steps within the run, as individual tests create entities
	// which the next entities need to reference. Don't mess too much with the
	// order or the content of sub-runs in test runs at this level.

	t.Run("HealthCheck", func(t *testing.T) {
		defer testSetup(t)

		w := httptest.NewRecorder()
		req := newRequest("GET", "/health", nil)
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			httpError(t, w, "health check failed")
		}
	})

	t.Run("Resource", func(t *testing.T) {
		defer testSetup(t)

		t.Run("Create", func(t *testing.T) {
			w := httptest.NewRecorder()
			body := []byte(`{"path": "/a"}`)
			req := newRequest("POST", "/resource", bytes.NewBuffer(body))
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusCreated {
				httpError(t, w, "couldn't create resource")
			}
			// make one-off struct to read the response into
			result := struct {
				_ interface{} `json:"created"`
			}{}
			err = json.Unmarshal(w.Body.Bytes(), &result)
			if err != nil {
				httpError(t, w, "couldn't read response from resource creation")
			}
		})

		t.Run("CreateSubresource", func(t *testing.T) {
			w := httptest.NewRecorder()
			body := []byte(`{"name": "b"}`)
			// try to create under the resource created with the previous test
			req := newRequest("POST", "/resource/a", bytes.NewBuffer(body))
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusCreated {
				httpError(t, w, "couldn't create resource")
			}
			expected := struct {
				_ interface{} `json:"created"`
			}{}
			err = json.Unmarshal(w.Body.Bytes(), &expected)
			if err != nil {
				httpError(t, w, "couldn't read response from resource creation")
			}
		})

		t.Run("ListSubresources", func(t *testing.T) {
			w := httptest.NewRecorder()
			req := newRequest("GET", "/resource/a", nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				httpError(t, w, "couldn't read resource")
			}
			result := struct {
				Path         string   `json:"path"`
				Name         string   `json:"name"`
				Subresources []string `json:"subresources"`
			}{}
			err = json.Unmarshal(w.Body.Bytes(), &result)
			if err != nil {
				httpError(t, w, "couldn't read response from resource listing")
			}
			msg := fmt.Sprintf("got response body: %s", w.Body.String())
			assert.Equal(t, "a", result.Name, msg)
			assert.Equal(t, "/a", result.Path, msg)
			assert.Equal(t, []string{"/a/b"}, result.Subresources, msg)
		})

		t.Run("Delete", func(t *testing.T) {
			w := httptest.NewRecorder()
			req := newRequest("DELETE", "/resource/a", nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusNoContent {
				httpError(t, w, "couldn't delete resource")
			}
		})

		t.Run("CheckDeleted", func(t *testing.T) {
			w := httptest.NewRecorder()
			req := newRequest("GET", "/resource/a", nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusNotFound {
				httpError(t, w, "deleted resource still present")
			}
		})

		t.Run("CheckDeletedSubresource", func(t *testing.T) {
			w := httptest.NewRecorder()
			req := newRequest("GET", "/resource/a/b", nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusNotFound {
				httpError(t, w, "deleted subresource still present")
			}
		})
	})

	t.Run("Role", func(t *testing.T) {
		defer testSetup(t)

		t.Run("Create", func(t *testing.T) {
			w := httptest.NewRecorder()
			body := []byte(`{
				"id": "foo",
				"permissions": [
					{"id": "foo", "action": {"service": "test", "method": "foo"}}
				]
			}`)
			req := newRequest("POST", "/role", bytes.NewBuffer(body))
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusCreated {
				httpError(t, w, "couldn't create role")
			}
			// make one-off struct to read the response into
			result := struct {
				_ interface{} `json:"created"`
			}{}
			err = json.Unmarshal(w.Body.Bytes(), &result)
			if err != nil {
				httpError(t, w, "couldn't read response from role creation")
			}
		})

		t.Run("Read", func(t *testing.T) {
			w := httptest.NewRecorder()
			req := newRequest("GET", "/role/foo", nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				httpError(t, w, "couldn't create role")
			}
			result := struct {
				Name string `json:"id"`
			}{}
			err = json.Unmarshal(w.Body.Bytes(), &result)
			if err != nil {
				httpError(t, w, "couldn't read response from role read")
			}
			msg := fmt.Sprintf("got response body: %s", w.Body.String())
			assert.Equal(t, "foo", result.Name, msg)
		})

		t.Run("Delete", func(t *testing.T) {
			w := httptest.NewRecorder()
			req := newRequest("DELETE", "/role/foo", nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusNoContent {
				httpError(t, w, "couldn't delete role")
			}
		})

		t.Run("CheckDeleted", func(t *testing.T) {
			w := httptest.NewRecorder()
			req := newRequest("GET", "/role/foo", nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusNotFound {
				httpError(t, w, "couldn't create role")
			}
		})
	})

	t.Run("Policy", func(t *testing.T) {
		defer testSetup(t)

		t.Run("Create", func(t *testing.T) {
			w := httptest.NewRecorder()
			// set up some resources to work with
			body := []byte(`{"path": "/a"}`)
			req := newRequest("POST", "/resource", bytes.NewBuffer(body))
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusCreated {
				httpError(t, w, "couldn't create resource")
			}
			w = httptest.NewRecorder()
			body = []byte(`{"path": "/a/b"}`)
			req = newRequest("POST", "/resource", bytes.NewBuffer(body))
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusCreated {
				httpError(t, w, "couldn't create resource")
			}
			w = httptest.NewRecorder()
			body = []byte(`{"path": "/a/b/c"}`)
			req = newRequest("POST", "/resource", bytes.NewBuffer(body))
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusCreated {
				httpError(t, w, "couldn't create resource")
			}
			// set up roles
			w = httptest.NewRecorder()
			body = []byte(`{
				"id": "bazgo-create",
				"permissions": [
					{
                        "id": "foo",
                        "action": {"service": "bazgo", "method": "create"}
                    }
				]
			}`)
			req = newRequest("POST", "/role", bytes.NewBuffer(body))
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusCreated {
				httpError(t, w, "couldn't create role")
			}
			// create the policy
			w = httptest.NewRecorder()
			body = []byte(`{
                "id": "bazgo-create-b",
                "resource_paths": ["/a/b"],
                "role_ids": ["bazgo-create"]
            }`)
			req = newRequest("POST", "/policy", bytes.NewBuffer(body))
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusCreated {
				httpError(t, w, "couldn't create policy")
			}
			result := struct {
				_ interface{} `json:"created"`
			}{}
			err = json.Unmarshal(w.Body.Bytes(), &result)
			if err != nil {
				httpError(t, w, "couldn't read response from resource creation")
			}
		})

		t.Run("Read", func(t *testing.T) {
			w := httptest.NewRecorder()
			req := newRequest("GET", "/policy/bazgo-create-b", nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				httpError(t, w, "policy not found")
			}
			result := struct {
				Name      string   `json:"id"`
				Resources []string `json:"resource_paths"`
				Roles     []string `json:"role_ids"`
			}{}
			err = json.Unmarshal(w.Body.Bytes(), &result)
			if err != nil {
				httpError(t, w, "couldn't read response from GET policy")
			}
			msg := fmt.Sprintf("got response body: %s", w.Body.String())
			assert.Equal(t, "bazgo-create-b", result.Name, msg)
			assert.Equal(t, []string{"/a/b"}, result.Resources, msg)
			assert.Equal(t, []string{"bazgo-create"}, result.Roles, msg)
		})
	})
}
