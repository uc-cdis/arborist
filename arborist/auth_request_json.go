package arborist

import (
	"encoding/json"
)

type AuthRequestJSON struct {
	PolicyIDs    []string    `json:"policies"`
	ResourcePath string      `json:"resource"`
	Action       Action      `json:"action"`
	Constraints  Constraints `json:"constraints,omitempty"`
}

func (requestJSON *AuthRequestJSON) UnmarshalJSON(data []byte) error {
	fields := make(map[string]interface{})
	err := json.Unmarshal(data, &fields)
	if err != nil {
		return err
	}
	optionalFields := map[string]struct{}{
		"constraints": struct{}{},
	}
	err = validateJSON("auth request", requestJSON, fields, optionalFields)
	if err != nil {
		return err
	}

	// Trick to use `json.Unmarshal` inside here, making a type alias which we
	// cast the AuthRequestJSON to.
	type loader AuthRequestJSON
	err = json.Unmarshal(data, (*loader)(requestJSON))
	if err != nil {
		return err
	}

	return nil
}

type BulkAuthRequestJSON struct {
	Requests []AuthRequestJSON `json:"requests"`
}
