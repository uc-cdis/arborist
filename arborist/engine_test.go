package arborist

import (
	"testing"
)

// makeTestEngine sets up a basic engine with a root node to use for testing.
func makeTestEngine() *Engine {
	engine := makeEngine()
	root, err := NewResource("", "root", nil, nil)
	if err != nil {
		panic(err)
	}
	engine.addResource(root)
	return engine
}

func TestRemoveResourceRecursively(t *testing.T) {
	engine := makeTestEngine()

	// Set up the resource tree to look like this:
	//
	//     /
	//       foo
	//         bar
	//           x
	//           y
	//       baz
	//
	// then remove the `bar` node recursively. Check that the bar, x, and y
	// nodes are gone, and foo and baz still exist.

	addResourceOrFail := func(resource *Resource, err error) *Resource {
		if err != nil {
			t.Fatalf("%s", err)
		}
		_, err = engine.addResource(resource)
		if err != nil {
			t.Fatalf("%s", err)
		}
		return resource
	}

	resource_foo := addResourceOrFail(NewResource(
		"foo",
		"example resource",
		engine.rootResource,
		nil,
	))
	_ = addResourceOrFail(NewResource(
		"baz",
		"example resource",
		engine.rootResource,
		nil,
	))
	resource_foo_bar := addResourceOrFail(NewResource(
		"bar",
		"example resource",
		resource_foo,
		nil,
	))
	_ = addResourceOrFail(NewResource(
		"x",
		"example resource",
		resource_foo_bar,
		nil,
	))
	_ = addResourceOrFail(NewResource(
		"y",
		"example resource",
		resource_foo_bar,
		nil,
	))

	// Check resources were added correctly.
	if _, exists := engine.resources["/foo/bar"]; !exists {
		t.Fatal("didn't create /foo/bar resource")
	}
	if _, exists := engine.resources["/foo/bar/x"]; !exists {
		t.Fatal("didn't create /foo/bar/x resource")
	}
	if _, exists := engine.resources["/foo/bar/y"]; !exists {
		t.Fatal("didn't create /foo/bar/y resource")
	}

	// Remove the /foo/bar node and check everything is as expected.
	engine.removeResourceRecursively(resource_foo_bar)
	if _, exists := engine.resources["/foo"]; !exists {
		t.Fatal("/foo/bar resource still exists")
	}
	if _, exists := engine.resources["/baz"]; !exists {
		t.Fatal("/foo/bar resource still exists")
	}
	if _, exists := engine.resources["/foo/bar"]; exists {
		t.Fatal("/foo/bar resource still exists")
	}
	if _, exists := engine.resources["/foo/bar/x"]; exists {
		t.Fatal("/foo/bar/x resource still exists")
	}
	if _, exists := engine.resources["/foo/bar/y"]; exists {
		t.Fatal("/foo/bar/y resource still exists")
	}
}
