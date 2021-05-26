package arborist

import (
	"errors"
	"fmt"

	"github.com/uc-cdis/go-authutils/authutils"
)

type TokenInfo struct {
	username string
	clientID string
	policies []string
}

func (server *Server) decodeToken(token string, scopes []string) (*TokenInfo, error) {
	missingRequiredField := func(field string) error {
		msg := fmt.Sprintf(
			"failed to decode token: missing required field `%s`",
			field,
		)
		return errors.New(msg)
	}
	fieldTypeError := func(field string) error {
		msg := fmt.Sprintf(
			"failed to decode token: field `%s` has wrong type",
			field,
		)
		return errors.New(msg)
	}
	server.logger.Debug("decoding token: %s", token)
	claims, err := server.jwtApp.Decode(token)
	if err != nil {
		return nil, fmt.Errorf("error decoding token: %s", err.Error())
	}
	expected := &authutils.Expected{Scopes: scopes}
	err = expected.Validate(claims)
	if err != nil {
		return nil, fmt.Errorf("error decoding token: %s", err.Error())
	}
	contextInterface, exists := (*claims)["context"]
	if !exists {
		return nil, missingRequiredField("context")
	}
	context, casted := contextInterface.(map[string]interface{})
	if !casted {
		return nil, fieldTypeError("context")
	}
	userInterface, exists := context["user"]
	if !exists {
		return nil, missingRequiredField("user")
	}
	user, casted := userInterface.(map[string]interface{})
	if !casted {
		return nil, fieldTypeError("user")
	}
	usernameInterface, exists := user["name"]
	if !exists {
		return nil, missingRequiredField("name")
	}
	username, casted := usernameInterface.(string)
	if !casted {
		return nil, fieldTypeError("name")
	}
	policiesInterface, exists := user["policies"]
	var policies []string = nil
	// it's ok if there's no policies in the token; we'll just look up the username
	if exists {
		// policiesInterface should really be a []string, so cast all the elements
		policiesInterfaceSlice, casted := policiesInterface.([]interface{})
		if !casted {
			return nil, fieldTypeError("policies")
		}
		policies := make([]string, len(policiesInterfaceSlice))
		for i, policyInterface := range policiesInterfaceSlice {
			policyString, casted := policyInterface.(string)
			if !casted {
				return nil, fieldTypeError("policies")
			}
			policies[i] = policyString
		}
	}
	clientID := ""
	clientIDInterface, exists := (*claims)["azp"]
	if exists {
		clientID, casted = clientIDInterface.(string)
		if !casted {
			return nil, fieldTypeError("azp")
		}
	}
	info := TokenInfo{
		username: username,
		clientID: clientID,
		policies: policies,
	}
	return &info, nil
}
