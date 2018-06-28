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
		Path:         resource.path,
		Description:  resource.description,
		Subresources: subresources,
	}
	return resourceJSON
}

// defaultsFromResource fills out the fields of a resourceJSON so that any
// empty fields in the JSON default to the contents of the resource. This can
// be used to allow JSON inputs for updating a resource to validate despite
// omitting some fields, which should mean to leave those alone without
// updating.
func (resourceJSON *ResourceJSON) defaultsFromResource(resource *Resource) {
	if resourceJSON.Name == "" {
		resourceJSON.Name = resource.name
	}
	if resourceJSON.Path == "" {
		resourceJSON.Path = resource.path
	}
	if resourceJSON.Description == "" {
		resourceJSON.Description = resource.description
	}
	if resourceJSON.Subresources == nil {
		subresources := make([]ResourceJSON, len(resource.subresources))
		for subresource := range resource.subresources {
			subresources = append(subresources, subresource.toJSON())
		}
		resourceJSON.Subresources = subresources
	}
}

func (resourceJSON *ResourceJSON) validate() error {
	if resourceJSON.Name == "" {
		return missingRequiredField("resource", "name")
	}
	return nil
}
