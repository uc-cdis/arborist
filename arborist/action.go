package arborist

import (
	"errors"
)

// The wildcard "*" in a permission or action field denotes that the field
// should validate against any input.
const WILDCARD string = "*"

// Representation of an action that a user attempts, which is a method operating
// on some resource belonging to some service.
type Action struct {
	Service  *Service
	Resource *Resource
	Method   string
}

func newAction() *Action {
	return &Action{
		Service:  nil,
		Resource: nil,
		Method:   "",
	}
}

// When we check if an action is valid, we want to know which parts of the
// request were or weren't valid; this struct keeps track of that.
type actionValidation struct {
	valid         bool
	validService  bool
	validMethod   bool
	validResource bool
}

// Return `true` if any of the service, method, or resource at least are valid.
func (v actionValidation) someValid() bool {
	return v.validService || v.validMethod || v.validResource
}

// Test this action against an attempted action `try_action` to see if
// `try_action` is allowed.
//
// Cost is `O(h_R)` where `h_R` is the height of the resource tree.
func (action Action) validate(try_action Action) actionValidation {
	// Service must match exactly.
	valid_service := action.Service == try_action.Service

	// Either the method must match or this method must be wildcard.
	valid_method := action.Method == try_action.Method || action.Method == WILDCARD

	// Either the resource must match, or this resource must be an ancestor of
	// the resource in the attempted action, or this action must be wildcard
	// (and allow for any action).
	same_resource := action.Resource.equals(*try_action.Resource)
	ancestor_resource := try_action.Resource.hasAncestor(*action.Resource)
	is_wildcard := action.Resource.ID == WILDCARD
	valid_resource := same_resource || is_wildcard || ancestor_resource

	all_valid := valid_service && valid_resource && valid_method

	return actionValidation{
		valid:         all_valid,
		validService:  valid_service,
		validMethod:   valid_method,
		validResource: valid_resource,
	}
}

func (action *Action) toJSON() ActionJSON {
	return ActionJSON{
		Service:  action.Service.ID,
		Resource: action.Resource.ID,
		Method:   action.Method,
	}
}

// Represent an `Action` in JSON format.
//
// *Only* used for marshalling actions to and from JSON.
type ActionJSON struct {
	Service  string `json:"service"`
	Resource string `json:"resource"`
	Method   string `json:"method"`
}

// Check that the fields in the action JSON are valid (non-empty).
func (actionJSON ActionJSON) validateFields() error {
	if actionJSON.Service == "" {
		err := errors.New("field `service` cannot be empty")
		return err
	}
	if actionJSON.Resource == "" {
		err := errors.New("field `resource` cannot be empty")
		return err
	}
	if actionJSON.Method == "" {
		err := errors.New("field `method` cannot be empty")
		return err
	}
	return nil
}
