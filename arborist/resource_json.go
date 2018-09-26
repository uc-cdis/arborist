package arborist

import (
	"encoding/json"
)

// toJSON converts a Resource to a ResourceJSON for serialization.
func (resource *Resource) toJSON() ResourceJSON {
	subresources := make([]ResourceJSON, len(resource.subresources))
	i := 0
	for subresource := range resource.subresources {
		subresources[i] = subresource.toJSON()
		i++
	}
	resourceJSON := ResourceJSON{
		Name:         resource.name,
		Path:         resource.path,
		Description:  resource.description,
		Subresources: subresources,
	}
	return resourceJSON
}

// ResoruceJSON defines a representation of a Resource that can be serialized
// directly into JSON using `json.Marshal`.
//
// A note on the fields here: either the resource must have been created
// through the subresources field of a parent resource, in which case the path
// is formed from the parent path joined with this resource's name, or with an
// explicit full path here.
type ResourceJSON struct {
	Name         string         `json:"name"`
	Path         string         `json:"path"`
	Description  string         `json:"description"`
	Subresources []ResourceJSON `json:"subresources"`
}

func (resourceJSON *ResourceJSON) UnmarshalJSON(data []byte) error {
	fields := make(map[string]interface{})
	err := json.Unmarshal(data, &fields)
	if err != nil {
		return err
	}
	optionalFields := map[string]struct{}{
		"description":  struct{}{},
		"subresources": struct{}{},
	}
	err = validateJSON("resource", resourceJSON, fields, optionalFields)
	if err != nil {
		return err
	}

	// Trick to use `json.Unmarshal` inside here, making a type alias which we
	// cast the ResourceJSON to.
	type loader ResourceJSON
	err = json.Unmarshal(data, (*loader)(resourceJSON))
	if err != nil {
		return err
	}

	if resourceJSON.Subresources == nil {
		resourceJSON.Subresources = []ResourceJSON{}
	}

	return nil
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

type ResourceBulkJSON struct {
	Resources []ResourceJSON `json:"resources"`
}
