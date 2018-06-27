package server

import (
	"encoding/json"
	"fmt"
	"net/http"
)

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
	w.Write(bytes)
	w.WriteHeader(http.StatusBadRequest)
}
