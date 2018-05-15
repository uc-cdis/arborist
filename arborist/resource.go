package arborist

import ()

// Resource is a representation of a thing to which access is controlled.
// Resources also have a hierarchical organization, where the children are
// meant to be finer-grained levels of authorization. Resources must be
// uniquely identified and the auth engine must maintain the collection of
// resource IDs, validating their uniqueness as they are added.
type Resource struct {
	ID           string
	subresources map[*Resource]struct{}
	parent       *Resource
}

// NewResource initializes a resource with the given ID and otherwise empty
// fields.
func NewResource(ID string) *Resource {
	return &Resource{
		ID:           ID,
		subresources: make(map[*Resource]struct{}),
		parent:       nil,
	}
}

// equals tests if two resources are equal. This is implemented just as their
// IDs matching.
func (resource *Resource) equals(other Resource) bool {
	return resource.ID == other.ID
}

// hasAncestor checks if this resource has a matching ancestor further up the
// tree.
func (resource *Resource) hasAncestor(other Resource) bool {
	// Start from this resource, and walk up the chain from parent to parent.
	var r *Resource = resource
	for r != nil {
		// Move the pointer up to the parent of the previous resource.
		r = r.parent
		// If we find the resource return true.
		if r.equals(other) {
			return true
		}
	}
	// Made it all the way up and never found a matching parent; return false.
	return false
}

// toJSON converts a `Resource` into a `ResourceJSON` which in turn can be
// used for serialization of the original resource into a JSON byte string.
func (resource *Resource) toJSON() ResourceJSON {
	var subresources []string
	for subresource := range resource.subresources {
		subresources = append(subresources, subresource.ID)
	}

	return ResourceJSON{
		ID:           resource.ID,
		Subresources: subresources,
		Parent:       resource.parent.ID,
	}
}

// ResourceJSON defines a JSON-de/serializable representation of a `Resource`.
type ResourceJSON struct {
	ID           string   `json:"id"`
	Subresources []string `json:"subresources"`
	Parent       string   `json:"parent"`
}
