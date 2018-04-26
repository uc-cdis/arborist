package arborist

import ()

const WILDCARD string = "*"

// NOTE that the resource can't be parsed directly from JSON, because we have to
// look it up in the engine to find the existing resource which has pointers to
// parent and child resources. Consequently, be careful not to use an action
// parsed straight out of a JSON; initialize the resource first.
type Action struct {
	Service    string `json:"service"`
	Resource   *Resource
	ResourceID string `json:"resource"`
	Method     string `json:"method"`
}

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
