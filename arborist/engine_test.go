package arborist

import (
	"testing"
)

// makeTestEngine sets up a basic engine with a root node to use for testing.
func makeTestEngine() *Engine {
	engine := makeEngine()
	root, err := NewResource("root", "root", nil, nil)
	if err != nil {
		panic(err)
	}
	engine.addResource(root)
	return engine
}

func makeTestEngineWithPolicies() *Engine {
	engine := makeTestEngine()
	addTestResources(engine)
	addTestRoles(engine)
	addTestPolicies(engine)
	return engine
}

// addTestResources sets up the resource tree to look like this:
//
//     / (root)
//     ├── coffee
//     │   ├── beans
//     │   ├── grinder
//     │   ├── filter
//     └── kitchen
//         ├── dishes
//         │   ├── kettle
//         │   └── mug
//         └── refrigerator
//             └── milk
//
// so that the engine has some basic resources set up to use for tests. Refer to
// this digram for what the test engine's resource tree should look like.
func addTestResources(engine *Engine) {
	addResourceOrFail := func(resource *Resource, err error) *Resource {
		if err != nil {
			// should never happen; resources added below are wrong somehow
			panic("fix addTestResources")
		}
		_, err = engine.addResource(resource)
		if err != nil {
			// should never happen; adding resource caused error from engine
			panic("fix addTestResources")
		}
		return resource
	}

	coffee := addResourceOrFail(NewResource(
		"coffee",
		"example resource",
		engine.rootResource,
		nil,
	))
	_ = addResourceOrFail(NewResource(
		"beans",
		"example resource",
		coffee,
		nil,
	))
	_ = addResourceOrFail(NewResource(
		"grinder",
		"example resource",
		coffee,
		nil,
	))
	_ = addResourceOrFail(NewResource(
		"filter",
		"example resource",
		coffee,
		nil,
	))

	kitchen := addResourceOrFail(NewResource(
		"kitchen",
		"example resource",
		engine.rootResource,
		nil,
	))
	dishes := addResourceOrFail(NewResource(
		"dishes",
		"example resource",
		kitchen,
		nil,
	))
	_ = addResourceOrFail(NewResource(
		"mug",
		"example resource",
		dishes,
		nil,
	))
	_ = addResourceOrFail(NewResource(
		"kettle",
		"example resource",
		dishes,
		nil,
	))
	refrigerator := addResourceOrFail(NewResource(
		"refrigerator",
		"example resource",
		kitchen,
		nil,
	))
	_ = addResourceOrFail(NewResource(
		"milk",
		"example resource",
		refrigerator,
		nil,
	))
}

// addTestRoles sets up some example roles in the engine to go with the
// resources.
func addTestRoles(engine *Engine) {
	addRoleOrFail := func(role *Role, err error) *Role {
		if err != nil {
			// should never happen; roles added below are wrong somehow
			panic("fix addTestRoles")
		}
		_, err = engine.addRole(role)
		if err != nil {
			// should never happen; adding role caused error from engine
			panic("fix addTestRoles")
		}
		return role
	}

	grind := &Permission{
		id:          "grind",
		description: "",
		action:      Action{"barista", "grind"},
		constraints: map[string]string{},
	}
	addRoleOrFail(NewRole(&Role{
		id:          "grind",
		description: "example role for grinding (beans)",
		permissions: map[*Permission]struct{}{grind: struct{}{}},
	}))

	boil := &Permission{
		id:          "boil",
		description: "",
		action:      Action{"barista", "boil"},
		constraints: map[string]string{},
	}
	addRoleOrFail(NewRole(&Role{
		id:          "boil",
		description: "example role for boiling (water)",
		permissions: map[*Permission]struct{}{boil: struct{}{}},
	}))

	pour := &Permission{
		id:          "pour",
		description: "",
		action:      Action{"barista", "pour"},
		constraints: map[string]string{},
	}
	addRoleOrFail(NewRole(&Role{
		id:          "pour",
		description: "example role for pouring (water)",
		permissions: map[*Permission]struct{}{pour: struct{}{}},
	}))
}

func addTestPolicies(engine *Engine) {
	engine.addPolicy(&Policy{
		id: "boil_water",
		roles: map[*Role]struct{}{
			engine.roles["boil"]: struct{}{},
		},
		resources: map[string]struct{}{
			"/kitchen/dishes/kettle": struct{}{},
		},
	})
}

func TestAddResources(t *testing.T) {
	// Setup an engine for testing and add the test resources.
	engine := makeTestEngine()
	addTestResources(engine)

	// Check resources were added correctly.
	check := func(path string) {
		if _, exists := engine.resources[path]; !exists {
			t.Fatalf("didn't create %s resource", path)
		}
	}
	check("/coffee")
	check("/coffee/beans")
	check("/coffee/grinder")
	check("/coffee/filter")
	check("/kitchen")
	check("/kitchen/dishes")
	check("/kitchen/dishes/mug")
	check("/kitchen/dishes/kettle")
	check("/kitchen/refrigerator")
	check("/kitchen/refrigerator/milk")
}

// checkRemoved is a helper function which fails a test if the resource with the
// given path still exists in the engine.
func checkRemoved(t *testing.T, engine *Engine, path string) {
	if _, exists := engine.resources[path]; exists {
		t.Fatalf("%s resource still exists", path)
	}
}

func TestRemoveResourceRecursively(t *testing.T) {
	engine := makeTestEngine()
	addTestResources(engine)

	// Remove the `refrigerator` node recursively. Check that the refrigerator
	// node is gone, and its child node `milk` is also gone, but that the other
	// nodes are still there.
	refrigerator := engine.resources["/kitchen/refrigerator"]
	engine.removeResourceRecursively(refrigerator)
	checkRemoved(t, engine, "/kitchen/refrigerator")
	checkRemoved(t, engine, "/kitchen/refrigerator/milk")

	// Remove the entire `kitchen` node recursively and check that subnodes are
	// removed.
	kitchen := engine.resources["/kitchen"]
	engine.removeResourceRecursively(kitchen)
	checkRemoved(t, engine, "/kitchen")
	checkRemoved(t, engine, "/kitchen/dishes")
	checkRemoved(t, engine, "/kitchen/dishes/mug")
}

func TestListAuthedResources(t *testing.T) {
	engine := makeTestEngineWithPolicies()

	t.Run("valid", func(t *testing.T) {
		listResourcesOrFail := func(policyIDs []string) []*Resource {
			resources, err := engine.listAuthedResources(policyIDs)
			if err != nil {
				t.Fatal(err.Error())
				return nil
			}
			return resources
		}

		check := func(resources []*Resource, expected []string) {
			resultPaths := make([]string, len(resources))
			for i := range resources {
				resultPaths[i] = resources[i].path
			}
		}

		resources := listResourcesOrFail([]string{"boil_water"})
		expected := []string{"/kitchen/dishes/kettle"}
		check(resources, expected)
	})

	t.Run("error", func(t *testing.T) {
		_, err := engine.listAuthedResources([]string{"not in the engine"})
		if err == nil {
			t.Error("no error from listing resources for missing policy")
		}

		_, err = engine.listAuthedResources([]string{"boil_water", "not in the engine"})
		if err == nil {
			t.Error("no error from listing resources for missing policy")
		}
	})
}
