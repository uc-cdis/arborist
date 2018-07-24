package arborist

import (
	"errors"
	"fmt"
	"strings"
)

func nameError(name string, purpose string, reason string) error {
	msg := fmt.Sprintf("invalid name %s for %s: %s", name, purpose, reason)
	return errors.New(msg)
}

func notExist(entity string, idType string, id string) error {
	msg := fmt.Sprintf("%s with %s `%s` does not exist", entity, idType, id)
	return errors.New(msg)
}

func alreadyExists(entity string, idType string, id string) error {
	msg := fmt.Sprintf("%s with %s %s already exists", entity, idType, id)
	return errors.New(msg)
}

func noDelete(entity string, idType string, identifier string, reason string) error {
	msg := fmt.Sprintf(
		"can't delete %s with %s %s; %s",
		entity,
		idType,
		identifier,
		reason,
	)
	return errors.New(msg)
}

func missingRequiredField(entity string, field string) error {
	msg := fmt.Sprintf("input %s is missing required field `%s`", entity, field)
	return errors.New(msg)
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
	return errors.New(msg)
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
	return errors.New(msg)
}
