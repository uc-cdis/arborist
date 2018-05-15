package arborist

import ()

// toJSON serializes an engine into AuthEngineJSON, which can in turn be
// converted to a byte string of the JSON representation of the engine.
func (engine *AuthEngine) toJSON() AuthEngineJSON {
	rootJSON := engine.root_role.toJSON()

	var resourcesJSON []ResourceJSON = make([]ResourceJSON, 0)
	for _, resource := range engine.resources {
		resourcesJSON = append(resourcesJSON, resource.toJSON())
	}

	var permissionsJSON []PermissionJSON = make([]PermissionJSON, 0)
	for _, permission := range engine.permissions {
		permissionsJSON = append(permissionsJSON, permission.toJSON())
	}

	var servicesJSON []ServiceJSON = make([]ServiceJSON, 0)
	for _, service := range engine.services {
		servicesJSON = append(servicesJSON, service.toJSON())
	}

	return AuthEngineJSON{
		RootRole:    rootJSON,
		Resources:   resourcesJSON,
		Permissions: permissionsJSON,
		Services:    servicesJSON,
	}
}

// AuthEngineJSON defines the intermediate-stage struct for de/serialization of
// the auth engine.
type AuthEngineJSON struct {
	RootRole    RoleJSON         `json:"root_role"`
	Resources   []ResourceJSON   `json:"resources"`
	Permissions []PermissionJSON `json:"permissions"`
	Services    []ServiceJSON    `json:"services"`
}
