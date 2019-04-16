package arborist

import (
	"fmt"
	"net/http"
	"strings"
)

type httpError struct {
	msg  string
	Code int
}

func (e *httpError) Error() string {
	return e.msg
}

func missingRequiredField(entity string, field string) error {
	msg := fmt.Sprintf("input %s is missing required field `%s`", entity, field)
	return &httpError{msg, http.StatusBadRequest}
}

func missingRequiredFields(entity string, fields []string) error {
	formattedFields := make([]string, len(fields))
	i := 0
	for _, field := range fields {
		formattedFields[i] = fmt.Sprintf("`%s`", field)
		i++
	}
	requiredFields := strings.Join(formattedFields, ", ")
	msg := fmt.Sprintf(
		"input %s is missing the following required fields: %s",
		entity,
		requiredFields,
	)
	return &httpError{msg, http.StatusBadRequest}
}

func containsUnexpectedFields(entity string, fields []string) error {
	formattedFields := make([]string, len(fields))
	i := 0
	for _, field := range fields {
		formattedFields[i] = fmt.Sprintf("`%s`", field)
		i++
	}
	requiredFields := strings.Join(formattedFields, ", ")
	msg := fmt.Sprintf(
		"input %s contains the following unexpected fields: %s",
		entity,
		requiredFields,
	)
	return &httpError{msg, http.StatusBadRequest}
}
