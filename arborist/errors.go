package arborist

import (
	"errors"
	"fmt"
)

func nameError(name string, purpose string, reason string) error {
	msg := fmt.Sprintf("invalid name %s for %s: %s", name, purpose, reason)
	return errors.New(msg)
}

func notExist(entity string, idType string, id string) error {
	msg := fmt.Sprintf("%s with %s %s does not exist", entity, idType, id)
	return errors.New(msg)
}
