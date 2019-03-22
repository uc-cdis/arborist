package server

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// ErrorJSON is a generic structure for containing error information.
type ErrorJSON struct {
	Error struct {
		Message string `json:"message"`
		Code    int    `json:"code"`
	} `json:"error"`
}

func newErrorJSON(message string, code int) ErrorJSON {
	return ErrorJSON{
		Error: struct {
			Message string `json:"message"`
			Code    int    `json:"code"`
		}{
			Message: message,
			Code:    code,
		},
	}
}

// write outputs the ErrorJSON onto the response writer.
func (errJSON ErrorJSON) write(w http.ResponseWriter, prettyJSON bool) error {
	var bytes []byte
	var err error
	if prettyJSON {
		bytes, err = json.MarshalIndent(errJSON, "", "    ")
	} else {
		bytes, err = json.Marshal(errJSON)
	}
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(errJSON.Error.Code)
	w.Write(bytes)
	return nil
}

func writeJSONReadError(w http.ResponseWriter, err error) {
	content := struct {
		Error string `json:"error"`
	}{
		Error: fmt.Sprintf("%s", err),
	}
	bytes, err := json.Marshal(content)
	if err != nil {
		panic(err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	w.Write(bytes)
}
