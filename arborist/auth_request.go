package arborist

import (
	"encoding/json"
)

type AuthRequest struct {
	User    AuthRequest_User    `json:"user"`
	Request AuthRequest_Request `json:"request"`
}

type AuthRequest_User struct {
	Token string `json:"token"`
	// The Policies field is optional, and if the request provides a token
	// this gets filled in by the first stage of handling by the engine, using
	// the Token field.
	Policies  []string `json:"policies,omitempty"`
	Audiences []string `json:"aud,omitempty"`
}

func (request *AuthRequest_User) Unmarshal(data []byte) error {
	fields := make(map[string]interface{})
	err := json.Unmarshal(data, &fields)
	if err != nil {
		return err
	}
	optionalFields := map[string]struct{}{
		"policies": struct{}{},
		"aud":      struct{}{},
	}
	err = validateJSON("auth request", request, fields, optionalFields)
	if err != nil {
		return err
	}

	// Trick to use `json.Unmarshal` inside here, making a type alias which we
	// cast the AuthRequest to.
	type loader AuthRequest_User
	err = json.Unmarshal(data, (*loader)(request))
	if err != nil {
		return err
	}

	return nil
}

type Constraints = map[string]string

type AuthRequest_Request struct {
	Resource    string      `json:"resource"`
	Action      Action      `json:"action"`
	Constraints Constraints `json:"constraints,omitempty"`
}

// Unmarshal defines the deserialization from  into an AuthRequest
// struct, which includes validating that required fields are present.
// (Required fields are anything not in the `optionalFields` variable.)
func (request *AuthRequest_Request) Unmarshal(data []byte) error {
	fields := make(map[string]interface{})
	err := json.Unmarshal(data, &fields)
	if err != nil {
		return err
	}
	optionalFields := map[string]struct{}{
		"constraints": struct{}{},
	}
	err = validateJSON("auth request", request, fields, optionalFields)
	if err != nil {
		return err
	}

	// Trick to use `json.Unmarshal` inside here, making a type alias which we
	// cast the AuthRequest to.
	type loader AuthRequest_Request
	err = json.Unmarshal(data, (*loader)(request))
	if err != nil {
		return err
	}

	return nil
}
