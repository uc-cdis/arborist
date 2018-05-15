package arborist

// Representation of a service that uses arborist for access control.
type Service struct {
	// The name for the service; should have uniqueness enforced by the
	// `AuthEngine`.
	ID string

	// Services can update arborist with entries mapping from URIs to resources,
	// so then arborist can be given just a URI in place of a resource ID and
	// translate that into the appropriate resource.
	uriToResource map[string]*Resource
}

// Create a new `Service`.
func NewService(id string) *Service {
	return &Service{
		ID:            id,
		uriToResource: make(map[string]*Resource),
	}
}

// Record (overwriting, if necessary) the mapping from a URI to a particular
// resource.
func (service *Service) addURI(uri string, resource *Resource) {
	service.uriToResource[uri] = resource
}

func (service *Service) toJSON() ServiceJSON {
	urisMap := make(map[string]string)
	for uri, resource := range service.uriToResource {
		urisMap[uri] = resource.ID
	}

	return ServiceJSON{
		ID:              service.ID,
		URIsToResources: urisMap,
	}
}

// Struct to handle parsing service from JSON.
type ServiceJSON struct {
	ID              string            `json:"id"`
	URIsToResources map[string]string `json:"uris_to_resources"`
}

func newServiceJSON() ServiceJSON {
	return ServiceJSON{
		URIsToResources: make(map[string]string),
	}
}
