package arborist_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
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
	clientID string
	policies []string
	exp      int64
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
	exp := testJWT.exp
	if exp == 0 {
		exp = time.Now().Unix() + 10000
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
				},
				"azp": "%s"
			}`,
			exp,
			testJWT.username,
			testJWT.clientID,
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
				},
				"azp": "%s"
			}`,
			time.Now().Unix()+10000,
			testJWT.username,
			policies,
			testJWT.clientID,
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

var logTo = flag.String(
	"log",
	"buffer",
	"where to write logs to (default is buffer flushed on errors)",
)

func TestServer(t *testing.T) {
	flag.Parse()
	logBuffer := bytes.NewBuffer([]byte{})
	logFlags := log.Ldate | log.Ltime
	var logDest io.Writer
	if *logTo == "stdout" {
		logDest = os.Stdout
	} else {
		logDest = logBuffer
	}
	logger := log.New(logDest, "", logFlags)

	jwtApp := &mockJWTApp{}

	dbUrl := os.Getenv("ARBORIST_TEST_DB")
	// if dbUrl is empty, should default to postgres environment
	if dbUrl == "" {
		fmt.Print("using postgres environment variables for test database\n")
	} else {
		fmt.Printf("using %s for test database\n", dbUrl)
	}
	db, err := sqlx.Open("postgres", dbUrl)
	// no error so far, make sure ping returns OK
	if err == nil {
		err = db.Ping()
	}
	if err != nil {
		fmt.Println("couldn't reach db; make sure arborist has correct database configuration!")
		t.Fatal(err)
	}
	fenceUrl := ""
	server, err := arborist.
		NewServer().
		WithLogger(logger).
		WithJWTApp(jwtApp).
		WithDB(db).
		WithFence(&fenceUrl).
		Init()
	if err != nil {
		t.Fatal(err)
	}
	handler := server.MakeRouter(logDest)

	// some test data to work with
	resourcePath := "/example(123)-X.Y*"
	resourceBody := []byte(fmt.Sprintf(`{"path": "%s"}`, resourcePath))
	serviceName := "zxcv"
	roleName := "hjkl"
	permissionName := "qwer"
	methodName := permissionName
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
		methodName,
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
			"name": "%s",
		 	"preferred_username": "%s"
		}`,
		username,
		username,
	))
	clientID := "qazwsx"
	clientBody := []byte(fmt.Sprintf(
		`{
			"clientID": "%s"
		}`,
		clientID,
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
				Name              string `json:"name"`
				PreferredUsername string `json:"preferred_username"`
			} `json:"created"`
		}{}
		err = json.Unmarshal(w.Body.Bytes(), &result)
		if err != nil {
			httpError(t, w, "couldn't read response from user creation")
		}
	}

	createClientBytes := func(t *testing.T, body []byte) {
		w := httptest.NewRecorder()
		req := newRequest("POST", "/client", bytes.NewBuffer(body))
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusCreated {
			httpError(t, w, "couldn't create client")
		}
		result := struct {
			Created struct {
				Name string `json:"name"`
			} `json:"created"`
		}{}
		err = json.Unmarshal(w.Body.Bytes(), &result)
		if err != nil {
			httpError(t, w, "couldn't read response from client creation")
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

	getResourceWithPath := func(t *testing.T, path string) arborist.ResourceOut {
		url := fmt.Sprintf("/resource%s", path)
		w := httptest.NewRecorder()
		req := newRequest("GET", url, nil)
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			httpError(t, w, fmt.Sprintf("couldn't find resource %s", path))
		}
		result := arborist.ResourceOut{}
		err := json.Unmarshal(w.Body.Bytes(), &result)
		if err != nil {
			httpError(t, w, "couldn't read response from resource get")
		}
		return result
	}

	getTagForResource := func(path string) string {
		var tags []string
		db.Select(&tags, "SELECT tag FROM resource WHERE path = $1", arborist.FormatPathForDb(path))
		if len(tags) == 0 {
			return ""
		}
		return tags[0]
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

	createGroupBytes := func(t *testing.T, body []byte) {
		w := httptest.NewRecorder()
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
	}

	resourcePathA := resourcePath + "/A"
	resourcePathB := resourcePath + "/B"

	setupTestPolicy := func(t *testing.T) {
		createResourceBytes(t, []byte(fmt.Sprintf(`{"path": "%s"}`, resourcePath)))
		createResourceBytes(t, []byte(fmt.Sprintf(`{"path": "%s"}`, resourcePathA)))
		createResourceBytes(t, []byte(fmt.Sprintf(`{"path": "%s"}`, resourcePathB)))
		createRoleBytes(
			t,
			[]byte(fmt.Sprintf(
				`{
					"id": "%s",
					"permissions": [
						{"id": "%s", "action": {"service": "%s", "method": "%s"}}
					]
				}`,
				roleName,
				permissionName,
				serviceName,
				methodName,
			)),
		)
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
		createPolicyBytes(t, policyBody)
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

	grantClientPolicy := func(t *testing.T, clientID string, policyName string) {
		w := httptest.NewRecorder()
		url := fmt.Sprintf("/client/%s/policy", clientID)
		req := newRequest(
			"POST",
			url,
			bytes.NewBuffer([]byte(fmt.Sprintf(`{"policy": "%s"}`, policyName))),
		)
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusNoContent {
			httpError(t, w, "couldn't grant policy to client")
		}
	}

	addUserToGroup := func(t *testing.T, username string, groupName string) {
		w := httptest.NewRecorder()
		url := fmt.Sprintf("/group/%s/user", groupName)
		req := newRequest(
			"POST",
			url,
			bytes.NewBuffer([]byte(fmt.Sprintf(`{"username": "%s"}`, username))),
		)
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusNoContent {
			httpError(t, w, "couldn't add user to group")
		}
	}

	grantGroupPolicy := func(t *testing.T, groupName string, policyName string) {
		w := httptest.NewRecorder()
		url := fmt.Sprintf("/group/%s/policy", groupName)
		req := newRequest(
			"POST",
			url,
			bytes.NewBuffer([]byte(fmt.Sprintf(`{"policy": "%s"}`, policyName))),
		)
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusNoContent {
			httpError(t, w, "couldn't grant policy to group")
		}
	}

	deleteEverything := func() {
		_ = db.MustExec("DELETE FROM policy_role")
		_ = db.MustExec("DELETE FROM policy_resource")
		_ = db.MustExec("DELETE FROM permission")
		_ = db.MustExec("DELETE FROM resource")
		_ = db.MustExec("DELETE FROM role")
		_ = db.MustExec("DELETE FROM usr_grp")
		_ = db.MustExec("DELETE FROM usr_policy")
		_ = db.MustExec("DELETE FROM client_policy")
		_ = db.MustExec("DELETE FROM grp_policy")
		_ = db.MustExec("DELETE FROM policy")
		_ = db.MustExec("DELETE FROM usr")
		_ = db.MustExec("DELETE FROM client")
		deleteGroups := fmt.Sprintf(
			"DELETE FROM grp WHERE (name != '%s' AND name != '%s')",
			arborist.AnonymousGroup,
			arborist.LoggedInGroup,
		)
		_ = db.MustExec(deleteGroups)
		_ = db.MustExec("DELETE FROM usr")
	}

	checkAuthSuccess := func(t *testing.T, body []byte) {
		w := httptest.NewRecorder()
		req := newRequest("POST", "/auth/request", bytes.NewBuffer(body))
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			httpError(t, w, "auth request failed")
		}
		result := struct {
			Auth bool `json:"auth"`
		}{}
		err := json.Unmarshal(w.Body.Bytes(), &result)
		if err != nil {
			httpError(t, w, "couldn't read response from auth request")
		}
		msg := fmt.Sprintf("got response body: %s", w.Body.String())
		assert.Equal(t, true, result.Auth, msg)
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

	t.Run("NotFound", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := newRequest("GET", "/bogus/url", nil)
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			httpError(t, w, "didn't get 404 for nonexistent URL")
		}
		result := struct {
			Error struct {
				Message string `json:"message"`
				Code    int    `json:"code"`
			} `json:"error"`
		}{}
		err = json.Unmarshal(w.Body.Bytes(), &result)
		if err != nil {
			httpError(t, w, "couldn't read response from 404 handler")
		}
		assert.Equal(t, 404, result.Error.Code, "unexpected response for 404")
	})

	t.Run("Resource", func(t *testing.T) {
		tearDown := testSetup(t)

		t.Run("ListEmpty", func(t *testing.T) {
			w := httptest.NewRecorder()
			req := newRequest("GET", "/resource", nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				httpError(t, w, "can't list resources")
			}
			result := struct {
				Resources []interface{} `json:"resources"`
			}{}
			err = json.Unmarshal(w.Body.Bytes(), &result)
			if err != nil {
				httpError(t, w, "couldn't read response from resources list")
			}
			msg := fmt.Sprintf("got response body: %s", w.Body.String())
			assert.Equal(t, []interface{}{}, result.Resources, msg)
		})

		t.Run("CreateWithError", func(t *testing.T) {
			t.Run("UnexpectedField", func(t *testing.T) {
				w := httptest.NewRecorder()
				// missing required field
				body := []byte(`{"path": "/a", "barrnt": "unexpected"}`)
				req := newRequest("POST", "/resource", bytes.NewBuffer(body))
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusBadRequest {
					httpError(t, w, "resource creation didn't fail as expected")
				}
			})

			t.Run("BadJSON", func(t *testing.T) {
				w := httptest.NewRecorder()
				req := newRequest("POST", "/resource", nil)
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusBadRequest {
					httpError(t, w, "expected 400 from request missing JSON")
				}
			})
		})

		// We're going to create a resource and save the tag into this variable
		// so we can test looking it up using the tag.
		var resourceTag string

		t.Run("Create", func(t *testing.T) {
			w := httptest.NewRecorder()
			path := "/a"
			name := "a"
			body := []byte(fmt.Sprintf(`{"path": "%s"}`, path))
			req := newRequest("POST", "/resource", bytes.NewBuffer(body))
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusCreated {
				httpError(t, w, "couldn't create resource")
			}
			// make one-off struct to read the response into
			result := struct {
				Resource struct {
					Name string `json:"name"`
					Path string `json:"path"`
					Tag  string `json:"tag"`
				} `json:"created"`
			}{}
			err = json.Unmarshal(w.Body.Bytes(), &result)
			if err != nil {
				httpError(t, w, "couldn't read response from resource creation")
			}
			msg := fmt.Sprintf("got response body: %s", w.Body.String())
			assert.Equal(t, name, result.Resource.Name, msg)
			assert.Equal(t, path, result.Resource.Path, msg)
			assert.NotEqual(t, "", result.Resource.Tag, msg)
			resourceTag = result.Resource.Tag

			t.Run("Punctuation", func(t *testing.T) {
				w := httptest.NewRecorder()
				body := []byte(`{"path": "/!@#punctuation$%^-_is_-&*(allowed)-==[].<>{},?\\"}`)
				req := newRequest("POST", "/resource", bytes.NewBuffer(body))
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusCreated {
					httpError(t, w, "couldn't create resource with punctuation")
				}
			})

			t.Run("AlreadyExists", func(t *testing.T) {
				w := httptest.NewRecorder()
				body := []byte(fmt.Sprintf(`{"path": "%s"}`, path))
				req := newRequest("POST", "/resource", bytes.NewBuffer(body))
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusConflict {
					httpError(t, w, "expected error from creating resource that already exists")
				}
			})

			t.Run("MissingParent", func(t *testing.T) {
				w := httptest.NewRecorder()
				body := []byte(`{"path": "/parent/doesnt/exist"}`)
				req := newRequest("POST", "/resource", bytes.NewBuffer(body))
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusBadRequest {
					httpError(t, w, "expected error from creating resource before parent exists")
				}
			})

			t.Run("CreateParents", func(t *testing.T) {
				w := httptest.NewRecorder()
				body := []byte(`{
					"path": "/parent/doesnt/exist",
					"description": "we did it"
				}`)
				req := newRequest("POST", "/resource?p", bytes.NewBuffer(body))
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusCreated {
					httpError(t, w, "could't create resource with parents")
				}
				getResourceWithPath(t, "/parent")
				getResourceWithPath(t, "/parent/doesnt")
				resource := getResourceWithPath(t, "/parent/doesnt/exist")
				assert.Equal(
					t,
					"we did it",
					resource.Description,
					"resource description doesn't match",
				)

				t.Run("AlreadyExists", func(t *testing.T) {
					w := httptest.NewRecorder()
					body := []byte(`{"path": "/parent/doesnt/exist"}`)
					req := newRequest("POST", "/resource?p", bytes.NewBuffer(body))
					handler.ServeHTTP(w, req)
					if w.Code != http.StatusConflict {
						httpError(t, w, "expected conflict from creating resource again")
					}
				})

				t.Run("SomeParentsExist", func(t *testing.T) {
					w := httptest.NewRecorder()
					body := []byte(`{"path": "/parent/sometimes/exist"}`)
					req := newRequest("POST", "/resource?p", bytes.NewBuffer(body))
					handler.ServeHTTP(w, req)
					if w.Code != http.StatusCreated {
						httpError(t, w, "couldn't create resource")
					}
				})
			})

			t.Run("RedundantSlashes", func(t *testing.T) {
				createResourceBytes(t, []byte(`{"path": "/too"}`))
				createResourceBytes(t, []byte(`{"path": "/too/many"}`))
				w := httptest.NewRecorder()
				path := "/too//many////slashes"
				body := []byte(fmt.Sprintf(`{"path": "%s"}`, path))
				req := newRequest("POST", "/resource", bytes.NewBuffer(body))
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusCreated {
					httpError(t, w, "couldn't create resource")
				}
				// make one-off struct to read the response into
				result := struct {
					Resource struct {
						Name string `json:"name"`
						Path string `json:"path"`
						Tag  string `json:"tag"`
					} `json:"created"`
				}{}
				err = json.Unmarshal(w.Body.Bytes(), &result)
				if err != nil {
					httpError(t, w, "couldn't read response from resource creation")
				}
				msg := fmt.Sprintf("got response body: %s", w.Body.String())
				assert.Equal(t, "slashes", result.Resource.Name, msg)
				assert.Equal(t, "/too/many/slashes", result.Resource.Path, msg)
				assert.NotEqual(t, "", result.Resource.Tag, msg)
			})
		})

		t.Run("ReadByTag", func(t *testing.T) {
			w := httptest.NewRecorder()
			url := fmt.Sprintf("/resource/tag/%s", resourceTag)
			req := newRequest("GET", url, nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				httpError(t, w, "couldn't create resource using tag")
			}
			result := struct {
				Name string `json:"name"`
				Path string `json:"path"`
				Tag  string `json:"tag"`
			}{}
			err = json.Unmarshal(w.Body.Bytes(), &result)
			if err != nil {
				httpError(t, w, "couldn't read response from resource creation")
			}
			msg := fmt.Sprintf("got response body: %s", w.Body.String())
			assert.Equal(t, "a", result.Name, msg)
			assert.Equal(t, "/a", result.Path, msg)
			assert.Equal(t, resourceTag, result.Tag, msg)
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

		t.Run("CreateWithSubresources", func(t *testing.T) {
			w := httptest.NewRecorder()
			body := []byte(`{
				"name": "x",
				"subresources": [
					{
						"name": "y",
						"subresources": [{"name": "z"}]
					}
				]
			}`)
			// try to create under the resource created with the previous test
			req := newRequest("POST", "/resource", bytes.NewBuffer(body))
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
			// now check that the child resources exist
			w = httptest.NewRecorder()
			req = newRequest("GET", "/resource/x/y", nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				httpError(t, w, "couldn't find subresource")
			}
			w = httptest.NewRecorder()
			req = newRequest("GET", "/resource/x/y/z", nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				httpError(t, w, "couldn't find subresource")
			}

			// re-POST the same x with different subresources should fail
			w = httptest.NewRecorder()
			body = []byte(`{
				"name": "x",
				"subresources": [
					{
						"name": "b",
						"subresources": [{"name": "c"}]
					}
				]
			}`)
			req = newRequest("POST", "/resource", bytes.NewBuffer(body))
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusConflict {
				httpError(t, w, "didn't conflict")
			}

			// use PUT (force-create) shall recreate the whole tree under x
			w = httptest.NewRecorder()
			req = newRequest("PUT", "/resource", bytes.NewBuffer(body))
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusCreated {
				httpError(t, w, "couldn't create resource")
			}
			expected = struct {
				_ interface{} `json:"created"`
			}{}
			err = json.Unmarshal(w.Body.Bytes(), &expected)
			if err != nil {
				httpError(t, w, "couldn't read response from resource creation")
			}

			// previous child resources should be gone
			w = httptest.NewRecorder()
			req = newRequest("GET", "/resource/x/y", nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusNotFound {
				httpError(t, w, "could find subresource")
			}
			w = httptest.NewRecorder()
			req = newRequest("GET", "/resource/x/y/z", nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusNotFound {
				httpError(t, w, "could find subresource")
			}

			// now check that the new child resources exist
			w = httptest.NewRecorder()
			req = newRequest("GET", "/resource/x/b", nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				httpError(t, w, "couldn't find subresource")
			}
			w = httptest.NewRecorder()
			req = newRequest("GET", "/resource/x/b/c", nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				httpError(t, w, "couldn't find subresource")
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

		t.Run("Overwrite", func(t *testing.T) {
			w := httptest.NewRecorder()
			body := []byte(`{
				"name": "Godel",
				"subresources": [
					{
						"name": "Escher",
						"subresources": [{"name": "Bach"}]
					}
				]
			}`)
			req := newRequest("PUT", "/resource", bytes.NewBuffer(body))
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusCreated {
				httpError(t, w, "couldn't create resource using PUT")
			}
			expected := struct {
				_ interface{} `json:"created"`
			}{}
			err = json.Unmarshal(w.Body.Bytes(), &expected)
			if err != nil {
				httpError(t, w, "couldn't read response from resource creation")
			}
			escherTag := getTagForResource("Godel.Escher")
			bachTag := getTagForResource("Godel.Escher.Bach")
			// now PUT over the same resource, but keep the subresources
			w = httptest.NewRecorder()
			body = []byte(`{
				"name": "Godel,",
				"subresources": [
					{"name": "Escher,", "subresources": [{"name": "Bach"}]},
					{"name": "completeness_theorem"}
				]
			}`)
			req = newRequest("PUT", "/resource", bytes.NewBuffer(body))
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusCreated {
				httpError(t, w, "couldn't update resource using PUT")
			}
			newEscherTag := getTagForResource("Godel.Escher")
			newBachTag := getTagForResource("Godel.Escher.Bach")
			assert.Equal(t, escherTag, newEscherTag, "subresource tag changed after PUT")
			assert.Equal(t, bachTag, newBachTag, "subresource tag changed after PUT")
			getResourceWithPath(t, "/Godel,/completeness_theorem")
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

			t.Run("AlreadyExists", func(t *testing.T) {
				w := httptest.NewRecorder()
				body := []byte(`{
					"id": "foo",
					"permissions": [
						{"id": "foo", "action": {"service": "test", "method": "foo"}}
					]
				}`)
				req := newRequest("POST", "/role", bytes.NewBuffer(body))
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusConflict {
					httpError(t, w, "expected conflict error from trying to create role again")
				}
			})

			t.Run("MissingPermissions", func(t *testing.T) {
				w := httptest.NewRecorder()
				body := []byte(`{"id": "no-permissions", "permissions": []}`)
				req := newRequest("POST", "/role", bytes.NewBuffer(body))
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusBadRequest {
					httpError(t, w, "expected error from trying to create role with no permissions")
				}
			})
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

		t.Run("List", func(t *testing.T) {
			w := httptest.NewRecorder()
			req := newRequest("GET", "/role", nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				httpError(t, w, "can't list roles")
			}
			result := struct {
				Roles []interface{} `json:"roles"`
			}{}
			err = json.Unmarshal(w.Body.Bytes(), &result)
			if err != nil {
				httpError(t, w, "couldn't read response from roles list")
			}
			msg := fmt.Sprintf("got response body: %s", w.Body.String())
			assert.Equal(t, 1, len(result.Roles), msg)
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

		roleName := "bazgo-create"
		policyName := "bazgo-create-b"

		t.Run("Create", func(t *testing.T) {
			w := httptest.NewRecorder()
			// set up some resources to work with
			// TODO: make more of this setup into "fixtures", not hard-coded
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
			body = []byte(fmt.Sprintf(
				`{
					"id": "%s",
					"permissions": [
						{
							"id": "foo",
							"action": {"service": "bazgo", "method": "create"}
						}
					]
				}`,
				roleName,
			))
			req = newRequest("POST", "/role", bytes.NewBuffer(body))
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusCreated {
				httpError(t, w, "couldn't create role")
			}
			// create the policy
			w = httptest.NewRecorder()
			body = []byte(fmt.Sprintf(
				`{
					"id": "%s",
					"resource_paths": ["/a/b"],
					"role_ids": ["%s"]
				}`,
				policyName,
				roleName,
			))
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

			t.Run("RoleNotExist", func(t *testing.T) {
				w := httptest.NewRecorder()
				createResourceBytes(t, []byte(`{"path": "/test_resource"}`))
				body := []byte(`{
					"id": "testPolicyRoleNotExist",
					"resource_paths": ["/test_resource"],
					"role_ids": ["does_not_exist"]
				}`)
				req = newRequest("POST", "/policy", bytes.NewBuffer(body))
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusBadRequest {
					httpError(t, w, "expected error creating policy with nonexistent role")
				}
			})

			t.Run("ResourceNotExist", func(t *testing.T) {
				w := httptest.NewRecorder()
				body := []byte(fmt.Sprintf(
					`{
						"id": "testPolicyResourceNotExist",
						"resource_paths": ["/does/not/exist"],
						"role_ids": ["%s"]
					}`,
					roleName,
				))
				req = newRequest("POST", "/policy", bytes.NewBuffer(body))
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusBadRequest {
					httpError(t, w, "expected error creating policy with nonexistent resource")
				}
			})
		})

		t.Run("Read", func(t *testing.T) {
			w := httptest.NewRecorder()
			url := fmt.Sprintf("/policy/%s", policyName)
			req := newRequest("GET", url, nil)
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
			assert.Equal(t, policyName, result.Name, msg)
			assert.Equal(t, []string{"/a/b"}, result.Resources, msg)
			assert.Equal(t, []string{roleName}, result.Roles, msg)
		})

		t.Run("Overwrite", func(t *testing.T) {
			createResourceBytes(t, []byte(`{"path": "/a/z"}`))
			w := httptest.NewRecorder()
			body := []byte(fmt.Sprintf(
				`{
					"id": "%s",
					"resource_paths": ["/a/z"],
					"role_ids": ["%s"]
				}`,
				policyName,
				roleName,
			))
			url := fmt.Sprintf("/policy/%s", policyName)
			req := newRequest("PUT", url, bytes.NewBuffer(body))
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusCreated {
				httpError(t, w, "couldn't put policy")
			}
			result := struct {
				Policy struct {
					Paths []string `json:"resource_paths"`
				} `json:"updated"`
			}{}
			err = json.Unmarshal(w.Body.Bytes(), &result)
			if err != nil {
				httpError(t, w, "couldn't read response from resource creation")
			}
			assert.Equal(t, []string{"/a/z"}, result.Policy.Paths)
		})

		t.Run("List", func(t *testing.T) {
			w := httptest.NewRecorder()
			req := newRequest("GET", "/policy", nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				httpError(t, w, "can't list policies")
			}
			result := struct {
				Policies []interface{} `json:"policies"`
			}{}
			err = json.Unmarshal(w.Body.Bytes(), &result)
			if err != nil {
				httpError(t, w, "couldn't read response from policies list")
			}
			msg := fmt.Sprintf("got response body: %s", w.Body.String())
			assert.Equal(t, 1, len(result.Policies), msg)
			// TODO (rudyardrichter, 2019-04-15): more checks here on response
		})

		t.Run("Delete", func(t *testing.T) {
			w := httptest.NewRecorder()
			req := newRequest("DELETE", "/policy/foo", nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusNoContent {
				httpError(t, w, "couldn't delete policy")
			}

			t.Run("NotExist", func(t *testing.T) {
				w := httptest.NewRecorder()
				req := newRequest("DELETE", "/policy/does-not-exist", nil)
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusNoContent {
					httpError(t, w, "expected 204 trying delete nonexistent policy")
				}
			})
		})

		t.Run("CheckDeleted", func(t *testing.T) {
			w := httptest.NewRecorder()
			req := newRequest("GET", "/policy/foo", nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusNotFound {
				httpError(t, w, "policy was not actually deleted")
			}
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
					"email": "%s",
					"preferred_username": "%s"
				}`,
				username,
				userEmail,
				username,
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

			t.Run("AlreadyExists", func(t *testing.T) {
				w := httptest.NewRecorder()
				body := []byte(fmt.Sprintf(
					`{
						"name": "%s",
						"email": "%s",
						"preferred_username": "%s"
					}`,
					username,
					userEmail,
					username,
				))
				req := newRequest("POST", "/user", bytes.NewBuffer(body))
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusConflict {
					httpError(t, w, "expected 409 from trying to create same user again")
				}
			})

			t.Run("MissingName", func(t *testing.T) {
				w := httptest.NewRecorder()
				body := []byte(`{"email": "asdf"}`)
				req := newRequest("POST", "/user", bytes.NewBuffer(body))
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusBadRequest {
					httpError(t, w, "expected 400 from trying to create user without name")
				}
			})
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
			assert.Equal(t, []string{}, result.Policies, msg)
			assert.Equal(t, []string{arborist.LoggedInGroup}, result.Groups, msg)
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
			req.Header.Add("X-AuthZ-Provider", "xxx")
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
				Name     string `json:"name"`
				Email    string `json:"email"`
				Policies []struct {
					Policy    string  `json:"policy"`
					ExpiresAt *string `json:"expires_at"`
				} `json:"policies"`
				Groups []string `json:"groups"`
			}{}
			err = json.Unmarshal(w.Body.Bytes(), &result)
			if err != nil {
				httpError(t, w, "couldn't read response from user read")
			}
			msg := fmt.Sprintf(
				"didn't grant policy correctly; got response body: %s",
				w.Body.String(),
			)
			assert.Len(t, result.Policies, 1, msg)
			assert.Equal(t, policyName, result.Policies[0].Policy, msg)
			assert.Nil(t, result.Policies[0].ExpiresAt, msg)

			t.Run("PolicyNotExist", func(t *testing.T) {
				w := httptest.NewRecorder()
				url := fmt.Sprintf("/user/%s/policy", username)
				req := newRequest(
					"POST",
					url,
					bytes.NewBuffer([]byte(`{"policy": "nonexistent"}`)),
				)
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusBadRequest {
					httpError(t, w, "didn't get 400 for nonexistent policy")
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

		t.Run("ListResources", func(t *testing.T) {
			w := httptest.NewRecorder()
			url := fmt.Sprintf("/user/%s/resources", username)
			req := newRequest("GET", url, nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				httpError(t, w, "couldn't list user's authed resources")
			}
			result := struct {
				Resources []string `json:"resources"`
			}{}
			err = json.Unmarshal(w.Body.Bytes(), &result)
			if err != nil {
				httpError(t, w, "couldn't read response from user resources")
			}
			msg := fmt.Sprintf(
				"didn't get expected resources; got response body: %s",
				w.Body.String(),
			)
			assert.Equal(t, []string{resourcePath}, result.Resources, msg)

			t.Run("UserNotFound", func(t *testing.T) {
				w := httptest.NewRecorder()
				req := newRequest("GET", "/user/nonexistent/resources", nil)
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusNotFound {
					httpError(t, w, "expected 404 trying to list resources for fake user")
				}
			})

			// TODO (rudyardrichter, 2019-05-09): also test response with tag
		})

		t.Run("RevokePolicy", func(t *testing.T) {
			test := func(authzProvider string, expected bool, msg string) {
				w := httptest.NewRecorder()
				url := fmt.Sprintf("/user/%s/policy/%s", username, policyName)
				req := newRequest("DELETE", url, nil)
				req.Header.Add("X-AuthZ-Provider", authzProvider)
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusNoContent {
					httpError(t, w, "couldn't revoke policy")
				}
				// look up user again and check if policy is still there
				w = httptest.NewRecorder()
				url = fmt.Sprintf("/user/%s", username)
				req = newRequest("GET", url, nil)
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusOK {
					httpError(t, w, "couldn't read user")
				}
				result := struct {
					Name     string `json:"name"`
					Email    string `json:"email"`
					Policies []struct {
						Name      string `json:"policy"`
						ExpiresAt string `json:"expires_at"`
					} `json:"policies"`
					Groups []string `json:"groups"`
				}{}
				err = json.Unmarshal(w.Body.Bytes(), &result)
				if err != nil {
					httpError(t, w, "couldn't read response from user read")
				}
				found := false
				for _, policy := range result.Policies {
					if policy.Name == policyName {
						found = true
						break
					}
				}
				if found != expected {
					assert.Fail(t, fmt.Sprintf(msg, w.Body.String()))
				}
			}
			test("yyy", true, "shouldn't revoke policy; got response body: %s")
			test("xxx", false, "didn't revoke policy correctly; got response body: %s")
		})

		timestamp := time.Now().Add(time.Hour).Format(time.RFC3339)

		t.Run("GrantPolicyWithExpiration", func(t *testing.T) {
			w := httptest.NewRecorder()
			url := fmt.Sprintf("/user/%s/policy", username)
			req := newRequest(
				"POST",
				url,
				bytes.NewBuffer([]byte(fmt.Sprintf(`{"policy": "%s", "expires_at": "%s"}`, policyName, timestamp))),
			)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusNoContent {
				httpError(t, w, "couldn't grant policy to user with expiration")
			}
		})

		t.Run("CheckPolicyHasExpiration", func(t *testing.T) {
			w := httptest.NewRecorder()
			url := fmt.Sprintf("/user/%s", username)
			req := newRequest("GET", url, nil)
			handler.ServeHTTP(w, req)
			result := struct {
				Policies []struct {
					Policy    string  `json:"policy"`
					ExpiresAt *string `json:"expires_at"`
				} `json:"policies"`
			}{}
			err := json.Unmarshal(w.Body.Bytes(), &result)
			if err != nil {
				httpError(t, w, "couldn't read response from user info")
			}
			assert.NotNil(t, result.Policies[0].ExpiresAt, "missing `expires_at` in response")
			expect, _ := time.Parse(time.RFC3339, timestamp)
			got, _ := time.Parse(time.RFC3339, *result.Policies[0].ExpiresAt)
			assert.True(t, expect.Equal(got), "wrong value for `expires_at`")
		})

		t.Run("Delete", func(t *testing.T) {
			w := httptest.NewRecorder()
			req := newRequest("DELETE", "/user/foo", nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusNoContent {
				httpError(t, w, "couldn't delete user")
			}

			t.Run("NotExist", func(t *testing.T) {
				w := httptest.NewRecorder()
				req := newRequest("DELETE", "/user/foo", nil)
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusNoContent {
					httpError(t, w, "expected 204 from trying to delete nonexistent user")
				}
			})
		})

		t.Run("DeleteNotExist", func(t *testing.T) {
			w := httptest.NewRecorder()
			url := fmt.Sprintf("/user/%s", username)
			req := newRequest("DELETE", url, nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusNoContent {
				httpError(t, w, "wrong response from deleting user that doesn't exist")
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

	t.Run("Client", func(t *testing.T) {
		tearDown := testSetup(t)

		clientID := "foo"

		t.Run("ListEmpty", func(t *testing.T) {
			w := httptest.NewRecorder()
			req := newRequest("GET", "/client", nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				httpError(t, w, "can't list clients")
			}
			result := struct {
				Clients interface{} `json:"clients"`
			}{}
			err = json.Unmarshal(w.Body.Bytes(), &result)
			if err != nil {
				httpError(t, w, "couldn't read response from clients list")
			}
			msg := fmt.Sprintf("got response body: %s", w.Body.String())
			assert.Equal(t, []interface{}{}, result.Clients, msg)
		})

		t.Run("NotFound", func(t *testing.T) {
			w := httptest.NewRecorder()
			req := newRequest("GET", "/client/nonexistent", nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusNotFound {
				httpError(t, w, "didn't get 404 for nonexistent client")
			}
		})

		// do some preliminary setup so we have a policy to work with
		createResourceBytes(t, resourceBody)
		createRoleBytes(t, roleBody)
		createPolicyBytes(t, policyBody)

		t.Run("Create", func(t *testing.T) {
			w := httptest.NewRecorder()
			body := []byte(fmt.Sprintf(
				`{
					"clientID": "%s",
					"policies": ["%s"]
				}`,
				clientID, policyName,
			))
			req := newRequest("POST", "/client", bytes.NewBuffer(body))
			req.Header.Add("X-AuthZ-Provider", "xxx")
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusCreated {
				httpError(t, w, "couldn't create client")
			}
			result := struct {
				_ interface{} `json:"created"`
			}{}
			err = json.Unmarshal(w.Body.Bytes(), &result)
			if err != nil {
				httpError(t, w, "couldn't read response from client creation")
			}
		})

		t.Run("Read", func(t *testing.T) {
			w := httptest.NewRecorder()
			url := fmt.Sprintf("/client/%s", clientID)
			req := newRequest("GET", url, nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				httpError(t, w, "couldn't read client")
			}
			result := struct {
				ClientID string   `json:"clientID"`
				Policies []string `json:"policies"`
			}{}
			err = json.Unmarshal(w.Body.Bytes(), &result)
			if err != nil {
				httpError(t, w, "couldn't read response from client read")
			}
			msg := fmt.Sprintf("got response body: %s", w.Body.String())
			assert.Equal(t, clientID, result.ClientID, msg)
			assert.Equal(t, []string{policyName}, result.Policies, msg)
		})

		t.Run("RevokePolicy", func(t *testing.T) {
			test := func(authzProvider string, expected bool, msg string) {
				w := httptest.NewRecorder()
				url := fmt.Sprintf("/client/%s/policy/%s", clientID, policyName)
				req := newRequest("DELETE", url, nil)
				req.Header.Add("X-AuthZ-Provider", authzProvider)
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusNoContent {
					httpError(t, w, "couldn't revoke policy")
				}
				// look up client again and check that policy is gone
				w = httptest.NewRecorder()
				url = fmt.Sprintf("/client/%s", clientID)
				req = newRequest("GET", url, nil)
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusOK {
					httpError(t, w, "couldn't read client")
				}
				result := struct {
					ClientID string   `json:"clientID"`
					Policies []string `json:"policies"`
				}{}
				err = json.Unmarshal(w.Body.Bytes(), &result)
				if err != nil {
					httpError(t, w, "couldn't read response from client read")
				}
				msg = fmt.Sprintf(msg, w.Body.String())
				if expected {
					assert.Contains(t, result.Policies, policyName, msg)
				} else {
					assert.NotContains(t, result.Policies, policyName, msg)
				}
			}
			test("yyy", true, "shouldn't revoke policy; got response body: %s")
			test("xxx", false, "didn't revoke policy correctly; got response body: %s")
		})

		t.Run("GrantPolicy", func(t *testing.T) {
			w := httptest.NewRecorder()
			url := fmt.Sprintf("/client/%s/policy", clientID)
			req := newRequest(
				"POST",
				url,
				bytes.NewBuffer([]byte(fmt.Sprintf(`{"policy": "%s"}`, policyName))),
			)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusNoContent {
				httpError(t, w, "couldn't grant policy to client")
			}
			// look up client again and check that policy is there
			w = httptest.NewRecorder()
			url = fmt.Sprintf("/client/%s", clientID)
			req = newRequest("GET", url, nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				httpError(t, w, "couldn't read client")
			}
			result := struct {
				ClientID string   `json:"clientID"`
				Policies []string `json:"policies"`
			}{}
			err = json.Unmarshal(w.Body.Bytes(), &result)
			if err != nil {
				httpError(t, w, "couldn't read response from client read")
			}
			msg := fmt.Sprintf(
				"didn't grant policy correctly; got response body: %s",
				w.Body.String(),
			)
			assert.Equal(t, []string{policyName}, result.Policies, msg)

			t.Run("PolicyNotExist", func(t *testing.T) {
				w := httptest.NewRecorder()
				url := fmt.Sprintf("/client/%s/policy", clientID)
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

			t.Run("ClientNotExist", func(t *testing.T) {
				w := httptest.NewRecorder()
				url := "/client/nonexistent/policy"
				req := newRequest(
					"POST",
					url,
					bytes.NewBuffer([]byte(fmt.Sprintf(`{"policy": "%s"}`, policyName))),
				)
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusNotFound {
					httpError(t, w, "didn't get 404 for nonexistent client")
				}
			})
		})

		t.Run("Delete", func(t *testing.T) {
			w := httptest.NewRecorder()
			req := newRequest("DELETE", "/client/foo", nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusNoContent {
				httpError(t, w, "couldn't delete client")
			}
		})

		t.Run("DeleteNotExist", func(t *testing.T) {
			w := httptest.NewRecorder()
			url := fmt.Sprintf("/client/%s", clientID)
			req := newRequest("DELETE", url, nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusNoContent {
				httpError(t, w, "wrong response from deleting client that doesn't exist")
			}
		})

		t.Run("CheckDeleted", func(t *testing.T) {
			w := httptest.NewRecorder()
			req := newRequest("GET", "/client/foo", nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusNotFound {
				httpError(t, w, "client was not actually deleted")
			}
		})

		tearDown(t)
	})

	t.Run("Group", func(t *testing.T) {
		tearDown := testSetup(t)

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

			t.Run("MissingName", func(t *testing.T) {
				w := httptest.NewRecorder()
				body := []byte(fmt.Sprintf(`{"users": ["%s"]}`, testGroupUser1))
				req := newRequest("POST", "/group", bytes.NewBuffer(body))
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusBadRequest {
					httpError(t, w, "expected 400 from creating group without name")
				}
			})

			t.Run("AlreadyExists", func(t *testing.T) {
				w := httptest.NewRecorder()
				body := []byte(fmt.Sprintf(`{"name": "%s"}`, testGroupName))
				req := newRequest("POST", "/group", bytes.NewBuffer(body))
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusConflict {
					httpError(t, w, "creating group that already exists didn't error as expected")
				}
			})
		})

		t.Run("List", func(t *testing.T) {
			w := httptest.NewRecorder()
			req := newRequest("GET", "/group", nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				httpError(t, w, "can't list groups")
			}
			result := struct {
				Groups []struct {
					Name string `json:"name"`
				} `json:"groups"`
			}{}
			err = json.Unmarshal(w.Body.Bytes(), &result)
			if err != nil {
				httpError(t, w, "couldn't read response from groups list")
			}
			msg := fmt.Sprintf("got response body: %s", w.Body.String())
			// check test group is in the results
			groupNames := []string{}
			for _, group := range result.Groups {
				groupNames = append(groupNames, group.Name)
			}
			assert.Contains(t, groupNames, testGroupName, msg)
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
				createUserBytes(t, []byte(fmt.Sprintf(`{"name": "%s", "preferred_username": "%s"}`, testUsername, testUsername)))
				w := httptest.NewRecorder()
				groupUserURL := fmt.Sprintf("/group/%s/user", testGroupName)
				body := []byte(fmt.Sprintf(`{"username": "%s", "preferred_username": "%s"}`, testUsername, testUsername))
				req := newRequest("POST", groupUserURL, bytes.NewBuffer(body))
				req.Header.Add("X-AuthZ-Provider", "xxx")
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusNoContent {
					httpError(t, w, "couldn't add user to group")
				}
			}

			t.Run("UserNotExist", func(t *testing.T) {
				w := httptest.NewRecorder()
				groupUserURL := fmt.Sprintf("/group/%s/user", testGroupName)
				body := []byte(`{"username": "does-not-exist"}`)
				req := newRequest("POST", groupUserURL, bytes.NewBuffer(body))
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusBadRequest {
					httpError(t, w, "expected 400 from trying to add nonexistent user to group")
				}
			})

			t.Run("GroupNotExist", func(t *testing.T) {
				w := httptest.NewRecorder()
				groupUserURL := "/group/does-not-exist/user"
				body := []byte(fmt.Sprintf(`{"username": "%s"}`, testGroupUser1))
				req := newRequest("POST", groupUserURL, bytes.NewBuffer(body))
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusNotFound {
					httpError(t, w, "expected 404 from trying to add user to nonexistent group")
				}
			})
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
			resultUsers := make([]string, len(result.Users))
			copy(resultUsers, result.Users)
			sort.Strings(resultUsers)
			expectUsers := make([]string, len(testGroupUsers))
			copy(expectUsers, testGroupUsers)
			sort.Strings(expectUsers)
			assert.Equal(t, expectUsers, resultUsers, msg)
		})

		t.Run("CreateWithUsers", func(t *testing.T) {
			groupName := "test-group-with-users"

			// create a group with some users in it
			w := httptest.NewRecorder()
			body := []byte(fmt.Sprintf(
				`{"name": "%s", "users": ["%s", "%s"]}`,
				groupName,
				testGroupUser1,
				testGroupUser2,
			))
			req := newRequest("POST", "/group", bytes.NewBuffer(body))
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusCreated {
				httpError(t, w, "couldn't create group")
			}
			result := struct {
				Created struct {
					Users []string `json:"users"`
				} `json:"created"`
			}{}
			err = json.Unmarshal(w.Body.Bytes(), &result)
			if err != nil {
				httpError(t, w, "couldn't read response from group creation")
			}
			sort.Strings(result.Created.Users)
			expectUsers := []string{testGroupUser1, testGroupUser2}
			sort.Strings(expectUsers)
			msg := fmt.Sprintf("didn't get expected users; got response body: %s", w.Body.String())
			assert.Equal(t, expectUsers, result.Created.Users, msg)

			// check that users were added correctly using read request
			w = httptest.NewRecorder()
			req = newRequest("GET", fmt.Sprintf("/group/%s", groupName), nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				httpError(t, w, "couldn't read group")
			}
			resultRead := struct {
				Users []string `json:"users"`
			}{}
			err = json.Unmarshal(w.Body.Bytes(), &resultRead)
			if err != nil {
				httpError(t, w, "couldn't read response from group read")
			}
			sort.Strings(resultRead.Users)
			msg = fmt.Sprintf("group doesn't have users; got response body: %s", w.Body.String())
			assert.Equal(t, expectUsers, resultRead.Users, msg)
		})

		userToRemove := testGroupUser1

		t.Run("RemoveUser", func(t *testing.T) {
			test := func(authzProvider string, expected bool, msg string) {
				w := httptest.NewRecorder()
				url := fmt.Sprintf("/group/%s/user/%s", testGroupName, userToRemove)
				req := newRequest("DELETE", url, nil)
				req.Header.Add("X-AuthZ-Provider", authzProvider)
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
				msg = fmt.Sprintf(msg, w.Body.String())
				if expected {
					assert.Contains(t, result.Users, userToRemove, msg)
				} else {
					assert.NotContains(t, result.Users, userToRemove, msg)
				}
			}
			test("yyy", true, "shouldn't remove user; got response body: %s")
			test("xxx", false, "didn't remove user; got response body: %s")
		})

		// do some preliminary setup so we have a policy to work with
		createResourceBytes(t, resourceBody)
		createRoleBytes(t, roleBody)
		createPolicyBytes(t, policyBody)

		t.Run("GrantPolicy", func(t *testing.T) {
			w := httptest.NewRecorder()
			url := fmt.Sprintf("/group/%s/policy", testGroupName)
			req := newRequest(
				"POST",
				url,
				bytes.NewBuffer([]byte(fmt.Sprintf(`{"policy": "%s"}`, policyName))),
			)
			req.Header.Add("X-AuthZ-Provider", "xxx")
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusNoContent {
				httpError(t, w, "couldn't grant policy to group")
			}
			// look up group again and check that policy is there
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
				url := fmt.Sprintf("/group/%s/policy", testGroupName)
				req := newRequest(
					"POST",
					url,
					bytes.NewBuffer([]byte(`{"policy": "nonexistent"}`)),
				)
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusBadRequest {
					httpError(t, w, "didn't get 400 for nonexistent policy")
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
					httpError(t, w, "didn't get 404 for nonexistent group")
				}
			})

			t.Run("InvalidJSON", func(t *testing.T) {
			})
		})

		t.Run("RevokePolicy", func(t *testing.T) {
			test := func(authzProvider string, expected bool, msg string) {
				w := httptest.NewRecorder()
				url := fmt.Sprintf("/group/%s/policy/%s", testGroupName, policyName)
				req := newRequest("DELETE", url, nil)
				req.Header.Add("X-AuthZ-Provider", authzProvider)
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusNoContent {
					httpError(t, w, "couldn't revoke policy from group")
				}
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
				msg = fmt.Sprintf(msg, w.Body.String())
				if expected {
					assert.Contains(t, result.Policies, policyName, msg)
				} else {
					assert.NotContains(t, result.Policies, policyName, msg)
				}
			}
			test("yyy", true, "shouldn't revoke policy; got response body: %s")
			test("xxx", false, "didn't revoke policy correctly; got response body: %s")
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

		t.Run("DeleteNotExist", func(t *testing.T) {
			w := httptest.NewRecorder()
			url := fmt.Sprintf("/group/%s", testGroupName)
			req := newRequest("DELETE", url, nil)
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusNoContent {
				httpError(t, w, "wrong response from deleting group that doesn't exist")
			}
		})

		t.Run("BuiltIn", func(t *testing.T) {
			groups := [][]string{
				[]string{arborist.AnonymousGroup, "Anonymous"},
				[]string{arborist.LoggedInGroup, "LoggedIn"},
			}
			for _, groupInfo := range groups {
				groupName := groupInfo[0]
				testName := groupInfo[1]
				t.Run(testName, func(t *testing.T) {
					t.Run("Exists", func(t *testing.T) {
						w := httptest.NewRecorder()
						req := newRequest("GET", fmt.Sprintf("/group/%s", groupName), nil)
						handler.ServeHTTP(w, req)
						if w.Code != http.StatusOK {
							httpError(t, w, "couldn't read group")
						}
						result := struct {
							Name  string   `json:"name"`
							Users []string `json:"users"`
							_     []string `json:"policies"`
						}{}
						err = json.Unmarshal(w.Body.Bytes(), &result)
						if err != nil {
							httpError(t, w, "couldn't read response from group read")
						}
						msg := fmt.Sprintf("got response body: %s", w.Body.String())
						assert.Equal(t, groupName, result.Name, msg)
						assert.Equal(t, []string{}, result.Users, msg)
					})

					t.Run("CannotDelete", func(t *testing.T) {
						w := httptest.NewRecorder()
						req := newRequest("DELETE", fmt.Sprintf("/group/%s", groupName), nil)
						handler.ServeHTTP(w, req)
						if w.Code != http.StatusBadRequest {
							msg := fmt.Sprintf(
								"expected error from trying to delete built-in group %s",
								groupName,
							)
							httpError(t, w, msg)
						}
					})

					t.Run("CannotAddUser", func(t *testing.T) {
						w := httptest.NewRecorder()
						username := "user-not-getting-added"
						body := []byte(fmt.Sprintf(`{"name": "%s"}`, username))
						req := newRequest("POST", "/user", bytes.NewBuffer(body))
						handler.ServeHTTP(w, req)

						w = httptest.NewRecorder()
						url := fmt.Sprintf("/group/%s/user", groupName)
						body = []byte(fmt.Sprintf(`{"username": "%s"}`, username))
						req = newRequest("POST", url, bytes.NewBuffer(body))
						handler.ServeHTTP(w, req)
						if w.Code != http.StatusBadRequest {
							httpError(t, w, "expected error adding user to built in group")
						}
					})
				})
			}
		})

		tearDown(t)
	})

	t.Run("Auth", func(t *testing.T) {
		tearDown := testSetup(t)

		t.Run("Mapping", func(t *testing.T) {
			setupTestPolicy(t)
			createUserBytes(t, userBody)
			grantUserPolicy(t, username, policyName)

			testAuthMappingResponse := func(t *testing.T, w *httptest.ResponseRecorder) {
				msg := fmt.Sprintf("got response body: %s", w.Body.String())
				assert.Equal(t, 200, w.Code, msg)
				result := make(map[string][]arborist.Action)
				err = json.Unmarshal(w.Body.Bytes(), &result)
				if err != nil {
					httpError(t, w, "couldn't read response from auth mapping")
				}
				msg = fmt.Sprintf("result does not contain expected resource %s", resourcePath)
				assert.Contains(t, result, resourcePath, msg)
				action := arborist.Action{Service: serviceName, Method: methodName}
				msg = fmt.Sprintf("result does not contain expected action %s", action)
				assert.Contains(t, result[resourcePath], action, msg)
			}

			t.Run("GET", func(t *testing.T) {
				w := httptest.NewRecorder()
				url := fmt.Sprintf("/auth/mapping?username=%s", username)
				req := newRequest("GET", url, nil)
				handler.ServeHTTP(w, req)
				testAuthMappingResponse(t, w)
			})

			t.Run("POST", func(t *testing.T) {
				w := httptest.NewRecorder()
				body := []byte(fmt.Sprintf(`{"username": "%s"}`, username))
				req := newRequest("POST", "/auth/mapping", bytes.NewBuffer(body))
				handler.ServeHTTP(w, req)
				testAuthMappingResponse(t, w)
			})
		})

		deleteEverything()

		t.Run("Request", func(t *testing.T) {
			setupTestPolicy(t)
			createUserBytes(t, userBody)
			grantUserPolicy(t, username, policyName)
			w := httptest.NewRecorder()
			token := TestJWT{username: username}
			body := []byte(fmt.Sprintf(
				`{
					"user": {"token": "%s"},
					"request": {
						"resource": "%s",
						"action": {
							"service": "%s",
							"method": "%s"
						}
					}
				}`,
				token.Encode(),
				resourcePath,
				serviceName,
				methodName,
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

			t.Run("Tag", func(t *testing.T) {
				w := httptest.NewRecorder()
				tag := getTagForResource(resourcePath)
				body := []byte(fmt.Sprintf(
					`{
						"user": {"token": "%s"},
						"request": {
							"resource": "%s",
							"action": {"service": "%s", "method": "%s"}
						}
					}`,
					token.Encode(),
					tag,
					serviceName,
					methodName,
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
			})

			t.Run("Unauthorized", func(t *testing.T) {
				w = httptest.NewRecorder()
				token = TestJWT{username: username}
				body = []byte(fmt.Sprintf(
					`{
						"user": {"token": "%s"},
						"request": {
							"resource": "%s",
							"action": {
								"service": "%s",
								"method": "%s"
							}
						}
					}`,
					token.Encode(),
					"/wrongresource", // TODO: get errors if these contain slashes
					serviceName,
					methodName,
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

			t.Run("BadRequest", func(t *testing.T) {

				t.Run("NotJSON", func(t *testing.T) {
					w = httptest.NewRecorder()
					token = TestJWT{username: username}
					body = []byte("not real JSON")
					req = newRequest("POST", "/auth/request", bytes.NewBuffer(body))
					handler.ServeHTTP(w, req)
					if w.Code != http.StatusBadRequest {
						httpError(t, w, "expected error")
					}
				})

				t.Run("MissingFields", func(t *testing.T) {
					w = httptest.NewRecorder()
					token = TestJWT{username: username}
					body = []byte(fmt.Sprintf(
						`{
							"user": {"token": "%s"}
						}`,
						token.Encode(),
					))
					req = newRequest("POST", "/auth/request", bytes.NewBuffer(body))
					handler.ServeHTTP(w, req)
					if w.Code != http.StatusBadRequest {
						httpError(t, w, "expected error from request missing fields")
					}
				})
			})

			createClientBytes(t, clientBody)

			t.Run("ClientForbidden", func(t *testing.T) {
				w = httptest.NewRecorder()
				token = TestJWT{username: username, clientID: clientID}
				body = []byte(fmt.Sprintf(
					`{
						"user": {"token": "%s"},
						"request": {
							"resource": "%s",
							"action": {
								"service": "%s",
								"method": "%s"
							}
						}
					}`,
					token.Encode(),
					resourcePath,
					serviceName,
					methodName,
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

			grantClientPolicy(t, clientID, policyName)

			t.Run("ClientBothOK", func(t *testing.T) {
				w = httptest.NewRecorder()
				token = TestJWT{username: username, clientID: clientID}
				body = []byte(fmt.Sprintf(
					`{
						"user": {"token": "%s"},
						"request": {
							"resource": "%s",
							"action": {
								"service": "%s",
								"method": "%s"
							}
						}
					}`,
					token.Encode(),
					resourcePath,
					serviceName,
					methodName,
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
				assert.Equal(t, true, result.Auth, msg)
			})
		})

		deleteEverything()

		t.Run("RequestMultiple", func(t *testing.T) {
			setupTestPolicy(t)
			createUserBytes(t, userBody)
			grantUserPolicy(t, username, policyName)
			w := httptest.NewRecorder()
			token := TestJWT{username: username}
			// TODO (rudyardrichter, 2019-04-22): this works just for testing
			// the `requests` thing but it would be better if it actually was
			// using distinct policies
			body := []byte(fmt.Sprintf(
				`{
					"user": {"token": "%s"},
					"requests": [
						{
							"resource": "%s",
							"action": {
								"service": "%s",
								"method": "%s"
							}
						},
						{
							"resource": "%s",
							"action": {
								"service": "%s",
								"method": "%s"
							}
						}
					]
				}`,
				token.Encode(),
				resourcePath,
				serviceName,
				methodName,
				resourcePath,
				serviceName,
				methodName,
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

			t.Run("UsingStar", func(t *testing.T) {
				createRoleBytes(
					t,
					[]byte(`{
						"id": "roleUsingStar",
						"permissions": [
							{"id": "serviceStar", "action": {"service": "*", "method": "read"}}
						]
					}`),
				)
				createPolicyBytes(
					t,
					[]byte(fmt.Sprintf(
						`{
							"id": "policyUsingStar",
							"resource_paths": ["%s"],
							"role_ids": ["roleUsingStar"]
						}`,
						resourcePath,
					)),
				)
				grantUserPolicy(t, username, "policyUsingStar")
				w := httptest.NewRecorder()
				token := TestJWT{username: username}
				body := []byte(fmt.Sprintf(
					`{
						"user": {"token": "%s"},
						"request": {
							"resource": "%s",
							"action": {
								"service": "shouldNotMatter",
								"method": "read"
							}
						}
					}`,
					token.Encode(),
					resourcePath,
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
			})

			t.Run("Unauthorized", func(t *testing.T) {
				w = httptest.NewRecorder()
				token = TestJWT{username: username}
				body = []byte(fmt.Sprintf(
					`{
						"user": {"token": "%s"},
						"requests": [
							{
								"resource": "%s",
								"action": {
									"service": "%s",
									"method": "%s"
								}
							},
							{
								"resource": "%s",
								"action": {
									"service": "%s",
									"method": "%s"
								}
							}
						]
					}`,
					token.Encode(),
					"/wrongresource", // TODO: get errors if these contain dashes
					serviceName,
					methodName,
					resourcePath,
					serviceName,
					methodName,
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
		})

		deleteEverything()

		t.Run("Anonymous", func(t *testing.T) {
			// user with a JWT also gets privileges from the anonymous group
			setupTestPolicy(t)
			createUserBytes(t, userBody)
			grantGroupPolicy(t, arborist.AnonymousGroup, policyName)
			w := httptest.NewRecorder()
			token := TestJWT{username: username}
			body := []byte(fmt.Sprintf(
				`{
					"user": {"token": "%s"},
					"request": {
						"resource": "%s",
						"action": {
							"service": "%s",
							"method": "%s"
						}
					}
				}`,
				token.Encode(),
				resourcePath,
				serviceName,
				methodName,
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
			// request with no JWT will still work if granted policy through
			// the anonymous group
			w = httptest.NewRecorder()
			body = []byte(fmt.Sprintf(
				`{
					"user": {"token": ""},
					"request": {
						"resource": "%s",
						"action": {
							"service": "%s",
							"method": "%s"
						}
					}
				}`,
				resourcePath,
				serviceName,
				methodName,
			))
			req = newRequest("POST", "/auth/request", bytes.NewBuffer(body))
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				httpError(t, w, "auth request failed")
			}
			// request should succeed, user has authorization
			result = struct {
				Auth bool `json:"auth"`
			}{}
			err = json.Unmarshal(w.Body.Bytes(), &result)
			if err != nil {
				httpError(t, w, "couldn't read response from auth request")
			}
			msg = fmt.Sprintf("got response body: %s", w.Body.String())
			assert.Equal(t, true, result.Auth, msg)

			t.Run("UsingStar", func(t *testing.T) {
				createRoleBytes(
					t,
					[]byte(`{
						"id": "roleForAnonUsingStar",
						"permissions": [
							{"id": "serviceStar", "action": {"service": "*", "method": "read"}}
						]
					}`),
				)
				createPolicyBytes(
					t,
					[]byte(fmt.Sprintf(
						`{
							"id": "policyForAnonUsingStar",
							"resource_paths": ["%s"],
							"role_ids": ["roleForAnonUsingStar"]
						}`,
						resourcePath,
					)),
				)
				grantGroupPolicy(t, arborist.AnonymousGroup, "policyForAnonUsingStar")
				authRequestBody := []byte(fmt.Sprintf(
					`{
						"user": {"token": ""},
						"request": {
							"resource": "%s",
							"action": {
								"service": "%s",
								"method": "%s"
							}
						}
					}`,
					resourcePath,
					serviceName,
					"read",
				))
				checkAuthSuccess(t, authRequestBody)
			})
		})

		deleteEverything()

		t.Run("LoggedIn", func(t *testing.T) {
			// user with a JWT gets privileges from the logged-in group
			setupTestPolicy(t)
			createUserBytes(t, userBody)
			grantGroupPolicy(t, arborist.LoggedInGroup, policyName)
			w := httptest.NewRecorder()
			token := TestJWT{username: username}
			body := []byte(fmt.Sprintf(
				`{
					"user": {"token": "%s"},
					"request": {
						"resource": "%s",
						"action": {
							"service": "%s",
							"method": "%s"
						}
					}
				}`,
				token.Encode(),
				resourcePath,
				serviceName,
				methodName,
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
		})

		deleteEverything()

		t.Run("Resources", func(t *testing.T) {
			createUserBytes(t, userBody)

			t.Run("Empty", func(t *testing.T) {
				w := httptest.NewRecorder()
				token := TestJWT{username: username}
				body := []byte(fmt.Sprintf(`{"user": {"token": "%s"}}`, token.Encode()))
				req := newRequest("POST", "/auth/resources", bytes.NewBuffer(body))
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusOK {
					httpError(t, w, "auth resources request failed")
				}
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

			createResourceBytes(t, resourceBody)
			createRoleBytes(t, roleBody)
			createPolicyBytes(t, policyBody)
			grantUserPolicy(t, username, policyName)

			t.Run("Granted", func(t *testing.T) {
				token := TestJWT{username: username}
				body := []byte(fmt.Sprintf(`{"user": {"token": "%s"}}`, token.Encode()))

				t.Run("GET", func(t *testing.T) {
					w := httptest.NewRecorder()
					req := newRequest("GET", "/auth/resources", nil)
					req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token.Encode()))
					handler.ServeHTTP(w, req)
					if w.Code != http.StatusOK {
						httpError(t, w, "auth resources request failed")
					}
					result := struct {
						Resources []string `json:"resources"`
					}{}
					err = json.Unmarshal(w.Body.Bytes(), &result)
					if err != nil {
						httpError(t, w, "couldn't read response from auth resources")
					}
					msg := fmt.Sprintf("got response body: %s", w.Body.String())
					assert.Equal(t, []string{resourcePath}, result.Resources, msg)
					// check the response returning tags is also correct
					w = httptest.NewRecorder()
					req = newRequest("GET", "/auth/resources?tags", nil)
					req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token.Encode()))
					handler.ServeHTTP(w, req)
					if w.Code != http.StatusOK {
						httpError(t, w, "auth resources request failed")
					}
					err = json.Unmarshal(w.Body.Bytes(), &result)
					if err != nil {
						httpError(t, w, "couldn't read response from auth resources")
					}
					msg = fmt.Sprintf("got response body: %s", w.Body.String())
					assert.Equal(t, 1, len(result.Resources), msg)
					if len(result.Resources) != 1 {
						t.Fatal()
					}
					tag := result.Resources[0]
					resource := getResourceWithPath(t, resourcePath)
					assert.Equal(t, resource.Tag, tag, "mismatched tag from auth resources list")
				})

				t.Run("POST", func(t *testing.T) {
					w := httptest.NewRecorder()
					req := newRequest("POST", "/auth/resources", bytes.NewBuffer(body))
					handler.ServeHTTP(w, req)
					if w.Code != http.StatusOK {
						httpError(t, w, "auth resources request failed")
					}
					result := struct {
						Resources []string `json:"resources"`
					}{}
					err = json.Unmarshal(w.Body.Bytes(), &result)
					if err != nil {
						httpError(t, w, "couldn't read response from auth resources")
					}
					msg := fmt.Sprintf("got response body: %s", w.Body.String())
					assert.Equal(t, []string{resourcePath}, result.Resources, msg)
					// check the response returning tags is also correct
					w = httptest.NewRecorder()
					req = newRequest("POST", "/auth/resources?tags", bytes.NewBuffer(body))
					handler.ServeHTTP(w, req)
					if w.Code != http.StatusOK {
						httpError(t, w, "auth resources request failed")
					}
					err = json.Unmarshal(w.Body.Bytes(), &result)
					if err != nil {
						httpError(t, w, "couldn't read response from auth resources")
					}
					msg = fmt.Sprintf("got response body: %s", w.Body.String())
					assert.Equal(t, 1, len(result.Resources), msg)
					if len(result.Resources) != 1 {
						t.Fatal()
					}
					tag := result.Resources[0]
					resource := getResourceWithPath(t, resourcePath)
					assert.Equal(t, resource.Tag, tag, "mismatched tag from auth resources list")
				})

				t.Run("Policies", func(t *testing.T) {
					w := httptest.NewRecorder()
					body := []byte(fmt.Sprintf(
						`{"user": {"token": "%s", "policies": ["%s"]}}`,
						token.Encode(),
						policyName,
					))
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

			t.Run("BadRequest", func(t *testing.T) {
				t.Run("NotJSON", func(t *testing.T) {
					w := httptest.NewRecorder()
					body := []byte("not real JSON")
					req := newRequest("POST", "/auth/resources", bytes.NewBuffer(body))
					handler.ServeHTTP(w, req)
					if w.Code != http.StatusBadRequest {
						httpError(t, w, "expected error")
					}
				})

				/*
					t.Run("MissingFields", func(t *testing.T) {
						w := httptest.NewRecorder()
						body := []byte(`{}`)
						req := newRequest("POST", "/auth/resources", bytes.NewBuffer(body))
						handler.ServeHTTP(w, req)
						fmt.Println(w.Body.String())
						if w.Code != http.StatusBadRequest {
							httpError(t, w, "expected error from request missing fields")
						}
					})
				*/
			})

			policyName := "client_policy"
			clientResourcePath := "/client_resource"
			resourceBody := []byte(fmt.Sprintf(`{"path": "%s"}`, clientResourcePath))
			policyBody := []byte(fmt.Sprintf(
				`{
					"id": "%s",
					"resource_paths": ["%s"],
					"role_ids": ["%s"]
				}`,
				policyName,
				clientResourcePath,
				roleName,
			))
			createClientBytes(t, clientBody)
			createResourceBytes(t, resourceBody)
			createPolicyBytes(t, policyBody)
			grantClientPolicy(t, clientID, policyName)
			grantUserPolicy(t, username, policyName)

			t.Run("Client", func(t *testing.T) {
				w := httptest.NewRecorder()
				token := TestJWT{username: username, clientID: clientID}
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
				assert.Contains(t, result.Resources, clientResourcePath, msg)
			})

			t.Run("Both", func(t *testing.T) {
				w := httptest.NewRecorder()
				token := TestJWT{username: username, clientID: clientID}
				body := []byte(fmt.Sprintf(`{"user": {"token": "%s"}}`, token.Encode()))
				req := newRequest("POST", "/auth/resources", bytes.NewBuffer(body))
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusOK {
					httpError(t, w, "auth resources request failed")
				}
				result := struct {
					Resources []string `json:"resources"`
				}{}
				err = json.Unmarshal(w.Body.Bytes(), &result)
				if err != nil {
					httpError(t, w, "couldn't read response from auth resources")
				}
				msg := fmt.Sprintf("got response body: %s", w.Body.String())
				assert.Contains(t, result.Resources, clientResourcePath, msg)
				assert.Contains(t, result.Resources, resourcePath, msg)
			})

			groupName := "test_resources_group"
			policyName = "group_policy"
			groupResourcePath := "/group_resource"
			resourceBody = []byte(fmt.Sprintf(`{"path": "%s"}`, groupResourcePath))
			policyBody = []byte(fmt.Sprintf(
				`{
					"id": "%s",
					"resource_paths": ["%s"],
					"role_ids": ["%s"]
				}`,
				policyName,
				groupResourcePath,
				roleName,
			))
			createResourceBytes(t, resourceBody)
			createPolicyBytes(t, policyBody)
			groupBody := []byte(fmt.Sprintf(
				`{
					"name": "%s",
					"policies": ["%s"],
					"users": []
				}`,
				groupName,
				policyName,
			))
			createGroupBytes(t, groupBody)
			addUserToGroup(t, username, groupName)

			t.Run("Group", func(t *testing.T) {
				w := httptest.NewRecorder()
				token := TestJWT{username: username, clientID: clientID}
				body := []byte(fmt.Sprintf(`{"user": {"token": "%s"}}`, token.Encode()))
				req := newRequest("POST", "/auth/resources", bytes.NewBuffer(body))
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusOK {
					httpError(t, w, "auth resources request failed")
				}
				result := struct {
					Resources []string `json:"resources"`
				}{}
				err = json.Unmarshal(w.Body.Bytes(), &result)
				if err != nil {
					httpError(t, w, "couldn't read response from auth resources")
				}
				msg := fmt.Sprintf("got response body: %s", w.Body.String())
				assert.Contains(t, result.Resources, groupResourcePath, msg)
				assert.Contains(t, result.Resources, resourcePath, msg)
			})
		})

		deleteEverything()

		t.Run("Proxy", func(t *testing.T) {
			createResourceBytes(t, resourceBody)
			createRoleBytes(t, roleBody)
			createPolicyBytes(t, policyBody)
			createUserBytes(t, userBody)
			grantUserPolicy(t, username, policyName)
			token := TestJWT{username: username}

			t.Run("Authorized", func(t *testing.T) {
				w := httptest.NewRecorder()
				authUrl := fmt.Sprintf(
					"/auth/proxy?resource=%s&service=%s&method=%s",
					url.QueryEscape(resourcePath),
					url.QueryEscape(serviceName),
					url.QueryEscape(methodName),
				)
				req := newRequest("GET", authUrl, nil)
				req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token.Encode()))
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusOK {
					httpError(t, w, "auth proxy request failed")
				}
			})

			t.Run("BadRequest", func(t *testing.T) {
				w := httptest.NewRecorder()
				authUrl := fmt.Sprintf(
					"/auth/proxy?resource=%s&service=%s&method=%s",
					url.QueryEscape("not-even-a-resource-path"),
					url.QueryEscape(serviceName),
					url.QueryEscape(methodName),
				)
				req := newRequest("GET", authUrl, nil)
				req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token.Encode()))
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusForbidden {
					httpError(t, w, "auth proxy request succeeded when it should not have")
				}
			})

			t.Run("Unauthorized", func(t *testing.T) {
				t.Run("BadHeader", func(t *testing.T) {
					w := httptest.NewRecorder()
					authUrl := fmt.Sprintf(
						"/auth/proxy?resource=%s&service=%s&method=%s",
						url.QueryEscape(resourcePath),
						url.QueryEscape(serviceName),
						url.QueryEscape(methodName),
					)
					req := newRequest("GET", authUrl, nil)
					req.Header.Add("Authorization", "Bearer garbage")
					handler.ServeHTTP(w, req)
					if w.Code != http.StatusUnauthorized {
						httpError(t, w, "auth proxy request succeeded when it should not have")
					}
				})

				t.Run("TokenExpired", func(t *testing.T) {
					token := TestJWT{username: username, exp: 1}
					w := httptest.NewRecorder()
					authUrl := fmt.Sprintf(
						"/auth/proxy?resource=%s&service=%s&method=%s",
						url.QueryEscape(resourcePath),
						url.QueryEscape(serviceName),
						url.QueryEscape(methodName),
					)
					req := newRequest("GET", authUrl, nil)
					req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token.Encode()))
					handler.ServeHTTP(w, req)
					if w.Code != http.StatusUnauthorized {
						httpError(t, w, "auth proxy request succeeded when it should not have")
					}
				})

				t.Run("ResourceNotExist", func(t *testing.T) {
					w := httptest.NewRecorder()
					authUrl := fmt.Sprintf(
						"/auth/proxy?resource=%s&service=%s&method=%s",
						url.QueryEscape("/not/authorized"),
						url.QueryEscape(serviceName),
						url.QueryEscape(methodName),
					)
					req := newRequest("GET", authUrl, nil)
					req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token.Encode()))
					handler.ServeHTTP(w, req)
					if w.Code != http.StatusForbidden {
						httpError(t, w, "auth proxy request succeeded when it should not have")
					}
				})

				t.Run("WrongMethod", func(t *testing.T) {
					w := httptest.NewRecorder()
					authUrl := fmt.Sprintf(
						"/auth/proxy?resource=%s&service=%s&method=%s",
						url.QueryEscape(resourcePath),
						url.QueryEscape(serviceName),
						url.QueryEscape("bogus_method"),
					)
					req := newRequest("GET", authUrl, nil)
					req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token.Encode()))
					handler.ServeHTTP(w, req)
					if w.Code != http.StatusForbidden {
						httpError(t, w, "auth proxy request succeeded when it should not have")
					}
				})

				t.Run("WrongService", func(t *testing.T) {
					w := httptest.NewRecorder()
					authUrl := fmt.Sprintf(
						"/auth/proxy?resource=%s&service=%s&method=%s",
						url.QueryEscape(resourcePath),
						url.QueryEscape("bogus_service"),
						url.QueryEscape(methodName),
					)
					req := newRequest("GET", authUrl, nil)
					req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token.Encode()))
					handler.ServeHTTP(w, req)
					if w.Code != http.StatusForbidden {
						httpError(t, w, "auth proxy request succeeded when it should not have")
					}
				})
			})

			t.Run("MissingAuthHeader", func(t *testing.T) {
				w := httptest.NewRecorder()
				// request is good
				authUrl := fmt.Sprintf(
					"/auth/proxy?resource=%s&service=%s&method=%s",
					url.QueryEscape(resourcePath),
					url.QueryEscape(serviceName),
					url.QueryEscape(methodName),
				)
				req := newRequest("GET", authUrl, nil)
				// but no header added to the request!
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusUnauthorized {
					httpError(t, w, "auth proxy request without auth header didn't fail as expected")
				}
			})

			t.Run("MissingMethod", func(t *testing.T) {
				w := httptest.NewRecorder()
				// omit method
				authUrl := fmt.Sprintf(
					"/auth/proxy?resource=%s&service=%s",
					url.QueryEscape(resourcePath),
					url.QueryEscape(serviceName),
				)
				req := newRequest("GET", authUrl, nil)
				req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token.Encode()))
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusBadRequest {
					httpError(t, w, "auth proxy request did not error as expected")
				}
			})

			t.Run("MissingService", func(t *testing.T) {
				w := httptest.NewRecorder()
				// omit service
				authUrl := fmt.Sprintf(
					"/auth/proxy?resource=%s&method=%s",
					url.QueryEscape(resourcePath),
					url.QueryEscape(methodName),
				)
				req := newRequest("GET", authUrl, nil)
				req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token.Encode()))
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusBadRequest {
					httpError(t, w, "auth proxy request did not error as expected")
				}
			})

			t.Run("MissingResource", func(t *testing.T) {
				w := httptest.NewRecorder()
				// omit resource
				authUrl := fmt.Sprintf(
					"/auth/proxy?&method=%sservice=%s",
					url.QueryEscape(methodName),
					url.QueryEscape(serviceName),
				)
				req := newRequest("GET", authUrl, nil)
				req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token.Encode()))
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusBadRequest {
					httpError(t, w, "auth proxy request did not error as expected")
				}
			})

			t.Run("Client", func(t *testing.T) {
				createClientBytes(t, clientBody)

				t.Run("Forbidden", func(t *testing.T) {
					w := httptest.NewRecorder()
					authUrl := fmt.Sprintf(
						"/auth/proxy?resource=%s&service=%s&method=%s",
						url.QueryEscape(resourcePath),
						url.QueryEscape(serviceName),
						url.QueryEscape(methodName),
					)
					req := newRequest("GET", authUrl, nil)
					token := TestJWT{username: username, clientID: clientID}
					req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token.Encode()))
					handler.ServeHTTP(w, req)
					if w.Code != http.StatusForbidden {
						httpError(t, w, "auth proxy request succeeded when it should not have")
					}
				})

				grantClientPolicy(t, clientID, policyName)

				t.Run("Granted", func(t *testing.T) {
					w := httptest.NewRecorder()
					authUrl := fmt.Sprintf(
						"/auth/proxy?resource=%s&service=%s&method=%s",
						url.QueryEscape(resourcePath),
						url.QueryEscape(serviceName),
						url.QueryEscape(methodName),
					)
					req := newRequest("GET", authUrl, nil)
					token := TestJWT{username: username, clientID: clientID}
					req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token.Encode()))
					handler.ServeHTTP(w, req)
					if w.Code != http.StatusOK {
						httpError(t, w, "auth proxy request failed")
					}
				})
			})
		})

		tearDown(t)
	})

	deleteEverything()
}
