package server

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestHandleListResourceAuth(t *testing.T) {
	jwt := `` // TODO
	inputJSON := struct {
		Token string `json:"token"`
	}{
		Token: jwt,
	}
	body, err := json.Marshal(inputJSON)
	if err != nil {
		// should never happen; fix above JSON struct
		panic(err)
	}
	reader := bytes.NewReader(body)
	r := httptest.NewRequest("POST", "http://arborist-service/auth/resources", reader)
	w := httptest.NewRecorder()

	server := makeTestServer()
	handler := server.handleListResourceAuth()
	handler.ServeHTTP(w, r)
	// TODO
}
