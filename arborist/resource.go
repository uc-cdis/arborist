package arborist

import (
	"strings"
	"unicode/utf8"
)

// pathString defines the conversion from a list of individual resource names,
// for instance `["root", "program", "project"]`, to the full path
// `"/root/program/project"`.
func pathString(segments []string) string {
	return strings.Join([]string{"/", strings.Join(segments, "/")}, "")
}

// Resource defines a resource in the RBAC model, which is some entity to which
// access should be controlled (such as a "project"). Policies bind Roles, which
// allow for some permissions, to a set of Resources.
//
// Resources are uniquely identified by their full path (the sequence of names
// starting from the root resource, continuing down to this one, joined by
// '/'), rather than their "name", which may be the same across different
// resources.
//
// Example serialization to JSON:
//
// {
//     "name": "foo",
//     "path": "/service-x/resource-foo",
//     "description": "some_resource",
//     "subresources": [
//         "description": "some_subresource",
//         "name": "bar",
//         "path": "/service-x/resource-foo/bar",
//         "subresources": [
//             ...
//         ]
//     ]
// }
type Resource struct {
	// The final name of the resource. Not globally unique.
	name string
	// The path for the resource, which is a list of strings used like a
	// filepath, and formatted similarly with slashes delimiting each node in
	// the path. Globally unique.
	path string
	// The individual resource names in the path.
	pathSegments []string
	// Some text describing the purpose of this resource.
	description string
	// Pointer to the parent node in the resource hierarchy. For example, if
	// the resource is `/projects/foo/bar`, the parent is `/projects/foo`.
	parent *Resource
	// Set of pointers to child nodes. Basically, thinking of this resource as
	// a directory, the subresources are the immediate contents of this
	// directory.
	subresources map[*Resource]struct{}
}

func validateResourceName(name string) error {
	if !utf8.Valid([]byte(name)) {
		return nameError(name, "resource", "only UTF8 allowed")
	}

	if strings.Contains(name, "/") {
		return nameError(name, "resource", "can't use reserved character '/'")
	}

	return nil
}

// NewResource sets up a new resource. If the parent is given then this
// resource is attached as a subresource, and its path will be computed
// accordingly (appending the name for this resource as the new last segment
// after the path of the parent node). Returns an error if the name is invalid
// as according to `validateResourceName`.
//
// NOTE: a resource may point to a parent resource, but until the engine runes
// `addResource` (or the parent is otherwise modified), the parent resource
// will not have a pointer to this resource as a subresource.
func NewResource(
	name string,
	description string,
	parent *Resource,
	subresources map[*Resource]struct{},
) (*Resource, error) {
	if err := validateResourceName(name); err != nil {
		return nil, err
	}

	var pathSegments []string
	if parent != nil {
		// For this case we have to copy the values out of the parent path
		// into this one.
		pathSegments = make([]string, len(parent.pathSegments)+1)
		for i, p := range parent.pathSegments {
			pathSegments[i] = p
		}
		pathSegments[len(parent.pathSegments)] = name
	} else {
		pathSegments = []string{name}
	}

	path := pathString(pathSegments)

	if subresources == nil {
		subresources = make(map[*Resource]struct{})
	}

	resource := &Resource{
		name:         name,
		path:         path,
		pathSegments: pathSegments,
		description:  description,
		parent:       parent,
		subresources: subresources,
	}

	if parent != nil {
		parent.addSubresource(resource)
	}

	return resource, nil
}

func (resource *Resource) addSubresource(sub *Resource) {
	resource.subresources[sub] = struct{}{}
	sub.parent = resource
}

func (resource *Resource) rmSubresource(sub *Resource) {
	delete(resource.subresources, sub)
	sub.parent = nil
}

func (resource *Resource) equals(other *Resource) bool {
	pathLen := len(resource.path)
	otherPathLen := len(other.path)
	if pathLen != otherPathLen {
		return false
	}
	for i := 0; i < pathLen; i++ {
		if resource.path[i] != other.path[i] {
			return false
		}
	}
	return true
}

// Traverse does a basic BFS starting at the given resource and traversing
// through all the subresources starting from that resource, writing the output
// to a channel. It receives a channel (`done`) which can indicate to cut off
// the output and return early.
//
// NOTE that the traversal order is not guaranteed to be anything in particular.
func (resource *Resource) traverse(done chan struct{}) <-chan *Resource {
	result := make(chan *Resource)

	go func() {
		var head *Resource
		defer close(result)
		queue := []*Resource{resource}
		for len(queue) > 0 {
			head, queue = queue[0], queue[1:]
			select {
			case result <- head:
			case <-done:
				return
			}
			for subnode := range head.subresources {
				queue = append(queue, subnode)
			}
		}
	}()

	return result
}
