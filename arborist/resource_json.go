package arborist

import ()

// ResoruceJSON defines a representation of a Resource that can be serialized
// directly into JSON using `json.Marshal`.
type ResourceJSON struct {
	Name         string         `json:"name"`
	Path         string         `json:"path"`
	Description  string         `json:"description"`
	Subresources []ResourceJSON `json:"subresources"`
}

// toJSON converts a Resource to a ResourceJSON for serialization.
func (resource *Resource) toJSON() ResourceJSON {
	subresources := make([]ResourceJSON, 0)
	for subresource := range resource.subresources {
		subresources = append(subresources, subresource.toJSON())
	}
	resourceJSON := ResourceJSON{
		Name:         resource.name,
		Path:         resource.pathString(),
		Description:  resource.description,
		Subresources: subresources,
	}
	return resourceJSON
}
