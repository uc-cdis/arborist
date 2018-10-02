package arborist

import (
	"sort"
	"testing"
)

// Wrapper function for creating a resource which assumes there's no error
// generated from invalid input etc.
func resource(
	name string,
	description string,
	parent *Resource,
	subresrouces map[*Resource]struct{},
) *Resource {
	resource, err := NewResource(name, description, parent, subresrouces)
	if err != nil {
		panic(err)
	}
	return resource
}

func TestTraverse(t *testing.T) {
	root := resource("root", "", nil, nil)
	node_0 := resource("a", "", root, nil)
	node_1 := resource("b", "", root, nil)
	// Create some subnodes that won't be used, just for more stuff in the
	// traversal.
	resource("c", "", node_0, nil)
	resource("d", "", node_0, nil)
	resource("e", "", node_1, nil)
	resource("f", "", node_1, nil)

	done := make(chan struct{})
	defer close(done)
	result := []string{}
	for resource := range root.traverse(done) {
		result = append(result, resource.name)
	}
	// The traversal order is not guaranteed to be exactly BFS because of the
	// channels implementation, so sort the results to check all the nodes are
	// visited.
	sort.Strings(result)
	expected := []string{"root", "a", "b", "c", "d", "e", "f"}
	sort.Strings(expected)

	// Check that all elements are the same in the result, and in BFS order.
	same := true
	lenResult := len(result)
	lenExpected := len(expected)
	if lenResult != lenExpected {
		same = false
	} else {
		for i := 0; i < lenResult; i++ {
			if result[i] != expected[i] {
				same = false
				break
			}
		}
	}

	if !same {
		t.Logf("result: %s", result)
		t.Logf("expected: %s", expected)
		t.FailNow()
	}
}

func TestPathString(t *testing.T) {
	check := func(expected string, result string) {
		if result != expected {
			t.Log("incorrect path")
			t.Logf("expected: %s", expected)
			t.Logf("result: %s", result)
			t.Fail()
		}
	}

	expected := "/root"
	result := pathString([]string{"root"})
	check(expected, result)

	expected = "/root/a/b/c"
	result = pathString([]string{"root", "a", "b", "c"})
	check(expected, result)
}

func TestParentPathString(t *testing.T) {
	check := func(expected string, result string) {
		if result != expected {
			t.Log("incorrect path")
			t.Logf("expected: %s", expected)
			t.Logf("result: %s", result)
			t.Fail()
		}
	}

	result := parentPathString("/a/b/c")
	expected := "/a/b"
	check(expected, result)

	result = parentPathString("/a")
	expected = "/"
	check(expected, result)
}

func TestResourcePath(t *testing.T) {
	root := resource("root", "", nil, nil)
	node_a := resource("a", "", root, nil)
	node_x := resource("x", "", root, nil)
	node_a_b := resource("b", "", node_a, nil)
	node_a_b_c := resource("c", "", node_a_b, nil)
	node_a_b_d := resource("d", "", node_a_b, nil)
	node_a_b_e := resource("e", "", node_a_b, nil)

	check := func(path string, expect string) {
		if path != expect {
			t.Logf("result: \"%s\"", path)
			t.Logf("expected: \"%s\"", expect)
			t.Fail()
		}
	}

	check(root.path, "/")
	check(node_a.path, "/a")
	check(node_x.path, "/x")
	check(node_a_b.path, "/a/b")
	check(node_a_b_c.path, "/a/b/c")
	check(node_a_b_d.path, "/a/b/d")
	check(node_a_b_e.path, "/a/b/e")
}

func TestEquals(t *testing.T) {
	root := resource("root", "", nil, nil)

	equals := root.equals(root)
	if !equals {
		t.Error("root != root")
	}

	subnode := resource("some_subnode", "", root, nil)

	equals = root.equals(subnode)
	if equals {
		t.Error("root == subnode")
	}
}
