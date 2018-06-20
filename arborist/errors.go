package arborist

import (
	"errors"
	"fmt"
)

func nameError(name string, purpose string, reason string) error {
	msg := fmt.Sprintf("invalid name %s for %s: %s", name, purpose, reason)
	return errors.New(msg)
}
