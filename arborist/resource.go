package arborist

import (
	"strings"
	"unicode/utf8"
)

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
//     "description": "some_resource",
//     "name": "foo",
//     "path": "/service-x/resource-foo",
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
	path []string
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

func NewResource(
	name string,
	description string,
	parent *Resource,
	subresources map[*Resource]struct{},
) (*Resource, error) {
	if err := validateResourceName(name); err != nil {
		return nil, err
	}

	var path []string
	if parent != nil {
		path = parent.path
	}
	path = append(path, name)

	// w h y
	newPath := make([]string, len(path))
	for i, p := range path {
		newPath[i] = p
	}

	if subresources == nil {
		subresources = make(map[*Resource]struct{})
	}

	resource := Resource{
		name:         name,
		path:         newPath,
		description:  description,
		parent:       parent,
		subresources: subresources,
	}

	if parent != nil {
		parent.subresources[&resource] = struct{}{}
	}

	return &resource, nil
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

func (resource *Resource) pathString() string {
	return strings.Join([]string{"/", strings.Join(resource.path, "/")}, "")
}

// Traverse does a basic BFS starting at the given resource and traversing
// through all the subresources starting from that resource, writing the output
// to a channel. It receives a channel (`done`) which can indicate to cut off
// the output and return early.
func (resource *Resource) traverse(done chan struct{}) <-chan *Resource {
	result := make(chan *Resource, 1)

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
