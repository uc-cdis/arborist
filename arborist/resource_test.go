package arborist

import (
	"testing"
)

func TestTraverse(t *testing.T) {
	root, err := NewResource("root", "", nil, nil)
	if err != nil {
		t.Fatalf("%s", err)
	}
	node_0, err := NewResource("a", "", root, nil)
	if err != nil {
		t.Fatalf("%s", err)
	}
	node_1, err := NewResource("b", "", root, nil)
	if err != nil {
		t.Fatalf("%s", err)
	}
	_, err = NewResource("c", "", node_0, nil)
	if err != nil {
		t.Fatalf("%s", err)
	}
	_, err = NewResource("d", "", node_0, nil)
	if err != nil {
		t.Fatalf("%s", err)
	}
	_, err = NewResource("e", "", node_1, nil)
	if err != nil {
		t.Fatalf("%s", err)
	}
	_, err = NewResource("f", "", node_1, nil)
	if err != nil {
		t.Fatalf("%s", err)
	}

	done := make(chan struct{})
	defer close(done)
	result := []string{}
	for resource := range root.traverse(done) {
		result = append(result, resource.name)
	}
	expected := []string{"root", "a", "b", "c", "d", "e", "f"}

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
	root, err := NewResource("root", "", nil, nil)
	if err != nil {
		t.Fatalf("%s", err)
	}
	node_a, err := NewResource("a", "", root, nil)
	if err != nil {
		t.Fatalf("%s", err)
	}
	node_x, err := NewResource("x", "", root, nil)
	if err != nil {
		t.Fatalf("%s", err)
	}
	node_a_b, err := NewResource("b", "", node_a, nil)
	if err != nil {
		t.Fatalf("%s", err)
	}

	node_a_b_c, err := NewResource("c", "", node_a_b, nil)
	if err != nil {
		t.Fatalf("%s", err)
	}

	node_a_b_d, err := NewResource("d", "", node_a_b, nil)
	if err != nil {
		t.Fatalf("%s", err)
	}

	node_a_b_e, err := NewResource("e", "", node_a_b, nil)
	if err != nil {
		t.Fatalf("%s", err)
	}

	check := func(path string, expect string) {
		if path != expect {
			t.Logf("result: \"%s\"", path)
			t.Logf("expected: \"%s\"", expect)
			t.Fail()
		}
	}

	check(root.pathString(), "/root")
	check(node_a.pathString(), "/root/a")
	check(node_x.pathString(), "/root/x")
	check(node_a_b.pathString(), "/root/a/b")
	check(node_a_b_c.pathString(), "/root/a/b/c")
	check(node_a_b_d.pathString(), "/root/a/b/d")
	check(node_a_b_e.pathString(), "/root/a/b/e")
}
