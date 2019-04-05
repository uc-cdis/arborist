package arborist_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/uc-cdis/arborist/arborist"
)

// For testing we use a mock JWT decoder which will always just return all the
// claims without trying to make HTTP calls or validating the token. The test
// server is set up using this mock JWT app to skip validation.
type mockJWTApp struct {
}

// Decode lets us use this mock JWT decoder for testing. It does zero validation
// of any tokens it receives, and just returns the decoded claims.
func (jwtApp *mockJWTApp) Decode(token string) (*map[string]interface{}, error) {
	decodedToken, err := jwt.ParseSigned(token)
	if err != nil {
		return nil, err
	}
	result := make(map[string]interface{})
	err = decodedToken.UnsafeClaimsWithoutVerification(&result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// TestJWT is a utility for making fake JWTs suitable for testing.
//
// Example:
//
//     token := TestJWT{username: username}
//     body := []byte(fmt.Sprintf(`{"user": {"token": "%s"}}`, token.Encode()))
//     req := newRequest("POST", "/auth/resources", bytes.NewBuffer(body))
//
type TestJWT struct {
	username string
	policies []string
}

// Encode takes the information in the TestJWT and creates a string of an
// encoded JWT containing some basic claims, and whatever information was
// provided in the TestJWT.
//
// To generate a signed JWT, we make up a random RSA key to sign the token ...
// and then throw away the key, because the server's mock JWT app (see above)
// doesn't care about the validation anyways.
func (testJWT *TestJWT) Encode() string {
	// Make a new, random RSA key just to sign this JWT.
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, nil)
	if err != nil {
		panic(err)
	}
	var payload []byte
	if testJWT.policies == nil || len(testJWT.policies) == 0 {
		payload = []byte(fmt.Sprintf(
			`{
				"aud": ["openid"],
				"exp": %d,
				"sub": "0",
				"context": {
					"user": {
						"name": "%s"
					}
				}
			}`,
			time.Now().Unix()+10000,
			testJWT.username,
		))
	} else {
		policies := fmt.Sprintf(`["%s"]`, strings.Join(testJWT.policies, `", "`))
		payload = []byte(fmt.Sprintf(
			`{
				"aud": ["openid"],
				"exp": %d,
				"sub": "0",
				"context": {
					"user": {
						"name": "%s",
						"policies": %s
					}
				}
			}`,
			time.Now().Unix()+10000,
			testJWT.username,
			policies,
		))
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		panic(err)
	}
	result, err := jws.CompactSerialize()
	if err != nil {
		panic(err)
	}
	return result
}

func TestServer(t *testing.T) {
	logBuffer := bytes.NewBuffer([]byte{})
	logFlags := log.Ldate | log.Ltime | log.Llongfile
	logger := log.New(logBuffer, "", logFlags)

	jwtApp := &mockJWTApp{}

	dbUrl := os.Getenv("ARBORIST_TEST_DB")
	// if dbUrl is empty, should default to postgres environment
	if dbUrl == "" {
		fmt.Print("using postgres environment variables for test database\n")
	} else {
		fmt.Printf("using %s for test database\n", dbUrl)
	}
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

	// some test data to work with
	resourcePath := "/example"
	resourceBody := []byte(fmt.Sprintf(`{"path": "%s"}`, resourcePath))
	serviceName := "zxcv"
	roleName := "hjkl"
	permissionName := "qwer"
	policyName := "asdf"
	roleBody := []byte(fmt.Sprintf(
		`{
			"id": "%s",
			"permissions": [
				{"id": "%s", "action": {"service": "%s", "method": "%s"}}
			]
		}`,
		roleName,
		permissionName,
		serviceName,
		permissionName,
	))
	policyBody := []byte(fmt.Sprintf(
		`{
			"id": "%s",
			"resource_paths": ["%s"],
			"role_ids": ["%s"]
		}`,
		policyName,
		resourcePath,
		roleName,
	))
	username := "wasd"
	userBody := []byte(fmt.Sprintf(
		`{
			"name": "%s"
		}`,
		username,
	))

	// httpError is a utility function which writes some useful output after an error.
	httpError := func(t *testing.T, w *httptest.ResponseRecorder, msg string) {
		t.Errorf("%s; got status %d, response: %s", msg, w.Code, w.Body.String())
		fmt.Println("test errored, dumping logs")
		fmt.Println("logs start")
		_, err = logBuffer.WriteTo(os.Stdout)
		fmt.Println("logs end")
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

	createUserBytes := func(t *testing.T, body []byte) {
		w := httptest.NewRecorder()
		req := newRequest("POST", "/user", bytes.NewBuffer(body))
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusCreated {
			httpError(t, w, "couldn't create user")
		}
		result := struct {
			Created struct {
				Name string `json:"name"`
			} `json:"created"`
		}{}
		err = json.Unmarshal(w.Body.Bytes(), &result)
		if err != nil {
			httpError(t, w, "couldn't read response from user creation")
		}
	}

	createResourceBytes := func(t *testing.T, body []byte) {
		w := httptest.NewRecorder()
		req := newRequest("POST", "/resource", bytes.NewBuffer(body))
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusCreated {
			httpError(t, w, "couldn't create resource")
		}
		result := struct {
			Created struct {
				Path string `json:"path"`
			} `json:"created"`
		}{}
		err = json.Unmarshal(w.Body.Bytes(), &result)
		if err != nil {
			httpError(t, w, "couldn't read response from resource creation")
		}
	}

	createRoleBytes := func(t *testing.T, body []byte) {
		w := httptest.NewRecorder()
		req := newRequest("POST", "/role", bytes.NewBuffer(body))
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusCreated {
			httpError(t, w, "couldn't create role")
		}
	}

	createPolicyBytes := func(t *testing.T, body []byte) {
		w := httptest.NewRecorder()
		req := newRequest("POST", "/policy", bytes.NewBuffer(body))
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusCreated {
			httpError(t, w, "couldn't create policy")
		}
		result := struct {
			_ interface{} `json:"created"`
		}{}
		err = json.Unmarshal(w.Body.Bytes(), &result)
		if err != nil {
			httpError(t, w, "couldn't read response from policy creation")
		}
	}

	grantUserPolicy := func(t *testing.T, username string, policyName string) {
		w := httptest.NewRecorder()
		url := fmt.Sprintf("/user/%s/policy", username)
		req := newRequest(
			"POST",
			url,
			bytes.NewBuffer([]byte(fmt.Sprintf(`{"policy": "%s"}`, policyName))),
		)
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusNoContent {
			httpError(t, w, "couldn't grant policy to user")
		}
	}

	deleteEverything := func() {
		_ = db.MustExec("DELETE FROM policy_role")
		_ = db.MustExec("DELETE FROM policy_resource")
		_ = db.MustExec("DELETE FROM permission")
		_ = db.MustExec("DELETE FROM resource WHERE (name != 'root')")
		_ = db.MustExec("DELETE FROM role")
		_ = db.MustExec("DELETE FROM usr_grp")
		_ = db.MustExec("DELETE FROM usr_policy")
		_ = db.MustExec("DELETE FROM grp_policy")
		_ = db.MustExec("DELETE FROM policy")
		_ = db.MustExec("DELETE FROM usr")
		_ = db.MustExec("DELETE FROM grp")
		_ = db.MustExec("DELETE FROM usr")
	}

	// testSetup should be used for any setup or teardown that should go in all
	// the tests. Use like this:
	//
	//     tearDown := testSetup(t)
	//     ...
	//     tearDown(t)
	//
	// `testSetup(t)` returns the teardown function, which when passed to defer
	// will run the teardown code at the end of the function.
	testSetup := func(t *testing.T) func(t *testing.T) {
		// ADD TEST SETUP HERE

		tearDown := func(t *testing.T) {
			// ADD TEST TEARDOWN HERE

			// wipe the database
			deleteEverything()

			// clear the logs currently stored in the buffer
			logBuffer.Reset()
		}

		return tearDown
	}

	// NOTE:
	//   - Every `t.Run` at this level should be completely isolated from the
	//     others, and clean up after itself.
	//   - Within the `t.Run` calls at this level, it's OK to have sequential
	//     tests that depend on results from the previous ones within that run.
	//     However, be careful not to shoot yourself in the foot.

	t.Run("HealthCheck", func(t *testing.T) {
		tearDown := testSetup(t)

		w := httptest.NewRecorder()
		req := newRequest("GET", "/health", nil)
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			httpError(t, w, "health check failed")
		}

		tearDown(t)
	})

	t.Run("Resource", func(t *testing.T) {
		tearDown := testSetup(t)

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

		tearDown(t)
	})

	t.Run("Role", func(t *testing.T) {
		tearDown := testSetup(t)

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
				httpError(t, w, "role was not actually deleted")
			}
		})

		tearDown(t)
	})

	t.Run("Policy", func(t *testing.T) {
		tearDown := testSetup(t)

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

		tearDown(t)
	})

	t.Run("User", func(t *testing.T) {
		tearDown := testSetup(t)

		username := "foo"
		userEmail := "foo@planx.net"

		t.Run("ListEmpty", func(t *testing.T) {
			w := httptest.NewRecorder()
			req := newRequest("GET", "/user", nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				httpError(t, w, "can't list users")
			}
			result := struct {
				Users interface{} `json:"users"`
			}{}
			err = json.Unmarshal(w.Body.Bytes(), &result)
			if err != nil {
				httpError(t, w, "couldn't read response from users list")
			}
			msg := fmt.Sprintf("got response body: %s", w.Body.String())
			assert.Equal(t, []interface{}{}, result.Users, msg)
		})

		t.Run("NotFound", func(t *testing.T) {
			w := httptest.NewRecorder()
			req := newRequest("GET", "/user/nonexistent", nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusNotFound {
				httpError(t, w, "didn't get 404 for nonexistent group")
			}
		})

		t.Run("Create", func(t *testing.T) {
			w := httptest.NewRecorder()
			body := []byte(fmt.Sprintf(
				`{
					"name": "%s",
					"email": "%s"
				}`,
				username,
				userEmail,
			))
			req := newRequest("POST", "/user", bytes.NewBuffer(body))
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusCreated {
				httpError(t, w, "couldn't create user")
			}
			result := struct {
				_ interface{} `json:"created"`
			}{}
			err = json.Unmarshal(w.Body.Bytes(), &result)
			if err != nil {
				httpError(t, w, "couldn't read response from user creation")
			}
		})

		t.Run("Read", func(t *testing.T) {
			w := httptest.NewRecorder()
			url := fmt.Sprintf("/user/%s", username)
			req := newRequest("GET", url, nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				httpError(t, w, "couldn't read user")
			}
			result := struct {
				Name     string   `json:"name"`
				Email    string   `json:"email"`
				Policies []string `json:"policies"`
				Groups   []string `json:"groups"`
			}{}
			err = json.Unmarshal(w.Body.Bytes(), &result)
			if err != nil {
				httpError(t, w, "couldn't read response from user read")
			}
			msg := fmt.Sprintf("got response body: %s", w.Body.String())
			assert.Equal(t, username, result.Name, msg)
			assert.Equal(t, userEmail, result.Email, msg)
			assert.Equal(t, []string{}, result.Policies, msg)
			assert.Equal(t, []string{}, result.Groups, msg)
		})

		// do some preliminary setup so we have a policy to work with
		createResourceBytes(t, resourceBody)
		createRoleBytes(t, roleBody)
		createPolicyBytes(t, policyBody)

		t.Run("GrantPolicy", func(t *testing.T) {
			w := httptest.NewRecorder()
			url := fmt.Sprintf("/user/%s/policy", username)
			req := newRequest(
				"POST",
				url,
				bytes.NewBuffer([]byte(fmt.Sprintf(`{"policy": "%s"}`, policyName))),
			)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusNoContent {
				httpError(t, w, "couldn't grant policy to user")
			}
			// look up user again and check that policy is there
			w = httptest.NewRecorder()
			url = fmt.Sprintf("/user/%s", username)
			req = newRequest("GET", url, nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				httpError(t, w, "couldn't read user")
			}
			result := struct {
				Name     string   `json:"name"`
				Email    string   `json:"email"`
				Policies []string `json:"policies"`
				Groups   []string `json:"groups"`
			}{}
			err = json.Unmarshal(w.Body.Bytes(), &result)
			if err != nil {
				httpError(t, w, "couldn't read response from user read")
			}
			msg := fmt.Sprintf(
				"didn't grant policy correctly; got response body: %s",
				w.Body.String(),
			)
			assert.Equal(t, []string{policyName}, result.Policies, msg)

			t.Run("PolicyNotExist", func(t *testing.T) {
				w := httptest.NewRecorder()
				url := fmt.Sprintf("/user/%s/policy", username)
				req := newRequest(
					"POST",
					url,
					bytes.NewBuffer([]byte(`{"policy": "nonexistent"}`)),
				)
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusNotFound {
					httpError(t, w, "didn't get 404 for nonexistent policy")
				}
			})

			t.Run("UserNotExist", func(t *testing.T) {
				w := httptest.NewRecorder()
				url := "/user/nonexistent/policy"
				req := newRequest(
					"POST",
					url,
					bytes.NewBuffer([]byte(fmt.Sprintf(`{"policy": "%s"}`, policyName))),
				)
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusNotFound {
					httpError(t, w, "didn't get 404 for nonexistent user")
				}
			})
		})

		t.Run("RevokePolicy", func(t *testing.T) {
			w := httptest.NewRecorder()
			url := fmt.Sprintf("/user/%s/policy/%s", username, policyName)
			req := newRequest("DELETE", url, nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusNoContent {
				httpError(t, w, "couldn't revoke policy")
			}
			// look up user again and check that policy is gone
			w = httptest.NewRecorder()
			url = fmt.Sprintf("/user/%s", username)
			req = newRequest("GET", url, nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				httpError(t, w, "couldn't read user")
			}
			result := struct {
				Name     string   `json:"name"`
				Email    string   `json:"email"`
				Policies []string `json:"policies"`
				Groups   []string `json:"groups"`
			}{}
			err = json.Unmarshal(w.Body.Bytes(), &result)
			if err != nil {
				httpError(t, w, "couldn't read response from user read")
			}
			msg := fmt.Sprintf(
				"didn't revoke policy correctly; got response body: %s",
				w.Body.String(),
			)
			assert.NotContains(t, result.Policies, policyName, msg)
		})

		t.Run("Delete", func(t *testing.T) {
			w := httptest.NewRecorder()
			req := newRequest("DELETE", "/user/foo", nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusNoContent {
				httpError(t, w, "couldn't delete user")
			}
		})

		t.Run("CheckDeleted", func(t *testing.T) {
			w := httptest.NewRecorder()
			req := newRequest("GET", "/user/foo", nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusNotFound {
				httpError(t, w, "user was not actually deleted")
			}
		})

		tearDown(t)
	})

	t.Run("Group", func(t *testing.T) {
		tearDown := testSetup(t)

		t.Run("ListEmpty", func(t *testing.T) {
			w := httptest.NewRecorder()
			req := newRequest("GET", "/group", nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				httpError(t, w, "can't list groups")
			}
			result := struct {
				Groups []interface{} `json:"groups"`
			}{}
			err = json.Unmarshal(w.Body.Bytes(), &result)
			if err != nil {
				httpError(t, w, "couldn't read response from groups list")
			}
			msg := fmt.Sprintf("got response body: %s", w.Body.String())
			assert.Equal(t, []interface{}{}, result.Groups, msg)
		})

		t.Run("NotFound", func(t *testing.T) {
			w := httptest.NewRecorder()
			req := newRequest("GET", "/group/nonexistent", nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusNotFound {
				httpError(t, w, "didn't get 404 for nonexistent group")
			}
		})

		testGroupName := "test-group"
		testGroupUser1 := "test-group-user-1"
		testGroupUser2 := "test-group-user-2"
		testGroupUser3 := "test-group-user-3"
		testGroupUsers := []string{
			testGroupUser1,
			testGroupUser2,
			testGroupUser3,
		}

		t.Run("Create", func(t *testing.T) {
			w := httptest.NewRecorder()
			body := []byte(fmt.Sprintf(`{"name": "%s"}`, testGroupName))
			req := newRequest("POST", "/group", bytes.NewBuffer(body))
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusCreated {
				httpError(t, w, "couldn't create group")
			}
			result := struct {
				_ interface{} `json:"created"`
			}{}
			err = json.Unmarshal(w.Body.Bytes(), &result)
			if err != nil {
				httpError(t, w, "couldn't read response from group creation")
			}
		})

		t.Run("Read", func(t *testing.T) {
			w := httptest.NewRecorder()
			req := newRequest("GET", fmt.Sprintf("/group/%s", testGroupName), nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				httpError(t, w, "couldn't read group")
			}
			result := struct {
				Name     string   `json:"name"`
				Users    []string `json:"users"`
				Policies []string `json:"policies"`
			}{}
			err = json.Unmarshal(w.Body.Bytes(), &result)
			if err != nil {
				httpError(t, w, "couldn't read response from group read")
			}
			msg := fmt.Sprintf("got response body: %s", w.Body.String())
			assert.Equal(t, testGroupName, result.Name, msg)
			assert.Equal(t, []string{}, result.Users, msg)
			assert.Equal(t, []string{}, result.Policies, msg)
		})

		t.Run("AddUsers", func(t *testing.T) {
			for _, testUsername := range testGroupUsers {
				createUserBytes(t, []byte(fmt.Sprintf(`{"name": "%s"}`, testUsername)))
				w := httptest.NewRecorder()
				groupUserURL := fmt.Sprintf("/group/%s/user", testGroupName)
				body := []byte(fmt.Sprintf(`{"username": "%s"}`, testUsername))
				req := newRequest("POST", groupUserURL, bytes.NewBuffer(body))
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusNoContent {
					httpError(t, w, "couldn't add user to group")
				}
			}
		})

		t.Run("CheckUsersAdded", func(t *testing.T) {
			w := httptest.NewRecorder()
			req := newRequest("GET", fmt.Sprintf("/group/%s", testGroupName), nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				httpError(t, w, "couldn't read group")
			}
			result := struct {
				Name     string   `json:"name"`
				Users    []string `json:"users"`
				Policies []string `json:"policies"`
			}{}
			err = json.Unmarshal(w.Body.Bytes(), &result)
			if err != nil {
				httpError(t, w, "couldn't read response from group read")
			}
			msg := fmt.Sprintf("got response body: %s", w.Body.String())
			assert.Equal(t, testGroupUsers, result.Users, msg)
		})

		userToRemove := testGroupUser1

		t.Run("RemoveUser", func(t *testing.T) {
			w := httptest.NewRecorder()
			url := fmt.Sprintf("/group/%s/user/%s", testGroupName, userToRemove)
			req := newRequest("DELETE", url, nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusNoContent {
				httpError(t, w, "couldn't remove user from group")
			}
			// look up group again and check that user is gone
			url = fmt.Sprintf("/group/%s", testGroupName)
			w = httptest.NewRecorder()
			req = newRequest("GET", url, nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				httpError(t, w, "couldn't read group")
			}
			result := struct {
				Name     string   `json:"name"`
				Users    []string `json:"users"`
				Policies []string `json:"policies"`
			}{}
			err = json.Unmarshal(w.Body.Bytes(), &result)
			if err != nil {
				httpError(t, w, "couldn't read response from group read")
			}
			msg := fmt.Sprintf("didn't remove user; got response body: %s", w.Body.String())
			assert.NotContains(t, result.Users, userToRemove, msg)
		})

		t.Run("GrantPolicy", func(t *testing.T) {
			// TODO: add group policy endpoint, enable test
			t.SkipNow()

			w := httptest.NewRecorder()
			url := fmt.Sprintf("/group/%s/policy", testGroupName)
			req := newRequest(
				"POST",
				url,
				bytes.NewBuffer([]byte(fmt.Sprintf(`{"policy": "%s"}`, policyName))),
			)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusNoContent {
				httpError(t, w, "couldn't grant policy to group")
			}
			// look up user again and check that policy is there
			w = httptest.NewRecorder()
			url = fmt.Sprintf("/group/%s", testGroupName)
			req = newRequest("GET", url, nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				httpError(t, w, "couldn't read group")
			}
			result := struct {
				Name     string   `json:"name"`
				Users    []string `json:"users"`
				Policies []string `json:"policies"`
			}{}
			err = json.Unmarshal(w.Body.Bytes(), &result)
			if err != nil {
				httpError(t, w, "couldn't read response from group read")
			}
			msg := fmt.Sprintf(
				"didn't grant policy correctly; got response body: %s",
				w.Body.String(),
			)
			assert.Equal(t, []string{policyName}, result.Policies, msg)

			t.Run("PolicyNotExist", func(t *testing.T) {
				w := httptest.NewRecorder()
				url := fmt.Sprintf("/group/%s/policy", username)
				req := newRequest(
					"POST",
					url,
					bytes.NewBuffer([]byte(`{"policy": "nonexistent"}`)),
				)
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusNotFound {
					httpError(t, w, "didn't get 404 for nonexistent policy")
				}
			})

			t.Run("GroupNotExist", func(t *testing.T) {
				w := httptest.NewRecorder()
				url := "/group/nonexistent/policy"
				req := newRequest(
					"POST",
					url,
					bytes.NewBuffer([]byte(fmt.Sprintf(`{"policy": "%s"}`, policyName))),
				)
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusNotFound {
					httpError(t, w, "didn't get 404 for nonexistent user")
				}
			})
		})

		t.Run("Delete", func(t *testing.T) {
			w := httptest.NewRecorder()
			url := fmt.Sprintf("/group/%s", testGroupName)
			req := newRequest("DELETE", url, nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusNoContent {
				httpError(t, w, "couldn't delete group")
			}
		})

		t.Run("CheckDeleted", func(t *testing.T) {
			w := httptest.NewRecorder()
			url := fmt.Sprintf("/group/%s", testGroupName)
			req := newRequest("GET", url, nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusNotFound {
				httpError(t, w, "group was not actually deleted")
			}
		})

		tearDown(t)
	})

	t.Run("Auth", func(t *testing.T) {
		tearDown := testSetup(t)

		t.Run("Request", func(t *testing.T) {
			createResourceBytes(t, []byte(`{"path": "/example"}`))
			createResourceBytes(t, []byte(`{"path": "/example/a"}`))
			createResourceBytes(t, []byte(`{"path": "/example/b"}`))
			createRoleBytes(
				t,
				[]byte(`{
					"id": "foo",
					"permissions": [
						{"id": "test", "action": {"service": "test", "method": "foo"}}
					]
				}`),
			)
			createRoleBytes(
				t,
				[]byte(`{
					"id": "bar",
					"permissions": [
						{"id": "test", "action": {"service": "test", "method": "bar"}}
					]
				}`),
			)
			createPolicyBytes(
				t,
				[]byte(`{
					"id": "example-policy-foo",
					"resource_paths": ["/example/a"],
					"role_ids": ["foo"]
				}`),
			)
			createPolicyBytes(
				t,
				[]byte(`{
					"id": "example-policy-bar",
					"resource_paths": ["/example/b"],
					"role_ids": ["bar"]
				}`),
			)
			createUserBytes(t, userBody)
			grantUserPolicy(t, username, "example-policy-foo")

			w := httptest.NewRecorder()
			token := TestJWT{username: username}
			body := []byte(fmt.Sprintf(
				`{
					"user": {"token": "%s"},
					"request": {
						"resource": "/example/a",
						"action": {
							"service": "test",
							"method": "foo"
						}
					}
				}`,
				token.Encode(),
			))
			req := newRequest("POST", "/auth/request", bytes.NewBuffer(body))
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				httpError(t, w, "auth request failed")
			}
			// request should succeed, user has authorization
			result := struct {
				Auth bool `json:"auth"`
			}{}
			err = json.Unmarshal(w.Body.Bytes(), &result)
			if err != nil {
				httpError(t, w, "couldn't read response from auth request")
			}
			msg := fmt.Sprintf("got response body: %s", w.Body.String())
			assert.Equal(t, true, result.Auth, msg)

			// test for authorization rejected
			w = httptest.NewRecorder()
			token = TestJWT{username: username}
			body = []byte(fmt.Sprintf(
				`{
					"user": {"token": "%s"},
					"request": {
						"resource": "/example/b",
						"action": {
							"service": "test",
							"method": "foo"
						}
					}
				}`,
				token.Encode(),
			))
			req = newRequest("POST", "/auth/request", bytes.NewBuffer(body))
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				httpError(t, w, "auth request failed")
			}
			// request should fail
			result = struct {
				Auth bool `json:"auth"`
			}{}
			err = json.Unmarshal(w.Body.Bytes(), &result)
			if err != nil {
				httpError(t, w, "couldn't read response from auth request")
			}
			msg = fmt.Sprintf("got response body: %s", w.Body.String())
			assert.Equal(t, false, result.Auth, msg)
		})

		t.Run("Resources", func(t *testing.T) {
			deleteEverything()

			t.Run("Empty", func(t *testing.T) {
				w := httptest.NewRecorder()
				token := TestJWT{username: username}
				body := []byte(fmt.Sprintf(`{"user": {"token": "%s"}}`, token.Encode()))
				req := newRequest("POST", "/auth/resources", bytes.NewBuffer(body))
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusOK {
					httpError(t, w, "auth resources request failed")
				}
				// in this case, since the user has zero access yet, should be empty
				result := struct {
					Resources []string `json:"resources"`
				}{}
				err = json.Unmarshal(w.Body.Bytes(), &result)
				if err != nil {
					httpError(t, w, "couldn't read response from auth resources")
				}
				msg := fmt.Sprintf("got response body: %s", w.Body.String())
				assert.Equal(t, []string{}, result.Resources, msg)
			})

			t.Run("Granted", func(t *testing.T) {
				createResourceBytes(t, resourceBody)
				createRoleBytes(t, roleBody)
				createPolicyBytes(t, policyBody)
				createUserBytes(t, userBody)
				grantUserPolicy(t, username, policyName)

				w := httptest.NewRecorder()
				token := TestJWT{username: username}
				body := []byte(fmt.Sprintf(`{"user": {"token": "%s"}}`, token.Encode()))
				req := newRequest("POST", "/auth/resources", bytes.NewBuffer(body))
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusOK {
					httpError(t, w, "auth resources request failed")
				}
				// in this case, since the user has zero access yet, should be empty
				result := struct {
					Resources []string `json:"resources"`
				}{}
				err = json.Unmarshal(w.Body.Bytes(), &result)
				if err != nil {
					httpError(t, w, "couldn't read response from auth resources")
				}
				msg := fmt.Sprintf("got response body: %s", w.Body.String())
				assert.Equal(t, []string{resourcePath}, result.Resources, msg)
			})
		})

		tearDown(t)
	})

	deleteEverything()
}
