package arborist

import (
	"encoding/json"
	"net/http"
)

type responseJSON interface {
	write(w http.ResponseWriter, r *http.Request) error
}

type jsonResponse struct {
	content interface{}
	code    int
}

func jsonResponseFrom(content interface{}, code int) *jsonResponse {
	return &jsonResponse{
		content: content,
		code:    code,
	}
}

func wantPrettyJSON(r *http.Request) bool {
	prettyJSON := false
	if r.Method == "GET" {
		prettyJSON = prettyJSON || r.URL.Query().Get("pretty") == "true"
		prettyJSON = prettyJSON || r.URL.Query().Get("prettyJSON") == "true"
	}
	return prettyJSON
}

func (response *jsonResponse) write(w http.ResponseWriter, r *http.Request) error {
	if response.code > 0 {
		w.WriteHeader(response.code)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	w.Header().Set("Content-Type", "application/json")
	var bytes []byte
	var err error
	if wantPrettyJSON(r) {
		bytes, err = json.MarshalIndent(response.content, "", "    ")
	} else {
		bytes, err = json.Marshal(response.content)
	}
	if err != nil {
		return err
	}
	_, err = w.Write(bytes)
	if err != nil {
		return err
	}
	return nil
}

type Error struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
}

type ErrorResponse struct {
	Error Error `json:"error"`
	// err stores an internal representation of an error in case it needs to be
	// tracked along with the http-ish version in `Error`.
	err error
}

func newErrorResponse(message string, code int, err *error) *ErrorResponse {
	response := &ErrorResponse{
		Error: Error{
			Message: message,
			Code:    code,
		},
	}
	if err != nil {
		response.err = *err
	}
	return response
}

func (errorResponse *ErrorResponse) write(w http.ResponseWriter, r *http.Request) error {
	var bytes []byte
	var err error

	prettyJSON := false
	if r.Method == "GET" {
		prettyJSON = prettyJSON || r.URL.Query().Get("pretty") == "true"
		prettyJSON = prettyJSON || r.URL.Query().Get("prettyJSON") == "true"
	}

	if prettyJSON {
		bytes, err = json.MarshalIndent(errorResponse, "", "    ")
	} else {
		bytes, err = json.Marshal(errorResponse)
	}
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(errorResponse.Error.Code)
	_, err = w.Write(bytes)
	if err != nil {
		return err
	}
	return nil
}
