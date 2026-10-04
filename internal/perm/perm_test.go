package perm

import "testing"

func TestAncestorsNearestFirst(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"/", []string{"/"}},
		{"/a", []string{"/a", "/"}},
		{"/a/b", []string{"/a/b", "/a", "/"}},
		{"/a/b/c", []string{"/a/b/c", "/a/b", "/a", "/"}},
	}
	for _, c := range cases {
		got := Ancestors(c.in)
		if len(got) != len(c.want) {
			t.Fatalf("Ancestors(%q) = %v, want %v", c.in, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("Ancestors(%q) = %v, want %v", c.in, got, c.want)
			}
		}
	}
}

func TestResolveInheritance(t *testing.T) {
	// allow on /a only: /a/b inherits it.
	entries := []Entry{
		{Path: "/a", AllowMask: int(ActionRead), Depth: 1},
	}
	if !Resolve(entries, "/a/b", ActionRead) {
		t.Fatal("child did not inherit the parent's allow")
	}
	if Resolve(entries, "/a/b", ActionWrite) {
		t.Fatal("write was granted by a read-only entry")
	}
}

// The key path from the task card: an explicit deny on a child overrides an
// inherited allow, even though the allow is the broader rule.
func TestResolveDenyOverridesInheritedAllow(t *testing.T) {
	entries := []Entry{
		{Path: "/a/b", DenyMask: int(ActionRead), Depth: 2}, // nearest
		{Path: "/a", AllowMask: int(ActionRead), Depth: 1},
		{Path: "/", AllowMask: int(ActionRead), Depth: 0},
	}
	if Resolve(entries, "/a/b", ActionRead) {
		t.Fatal("explicit deny on the child was overridden by an inherited allow")
	}
	// A sibling still inherits normally.
	if !Resolve(entries, "/a/c", ActionRead) {
		t.Fatal("deny on /a/b leaked to the sibling /a/c")
	}
}

func TestResolveNoEntriesMeansNoAccess(t *testing.T) {
	if Resolve(nil, "/a", ActionRead) {
		t.Fatal("empty ACL granted access; silence must not be permission")
	}
}

func TestResolveMostSpecificAllowWins(t *testing.T) {
	entries := []Entry{
		{Path: "/a/b", AllowMask: int(ActionDelete), Depth: 2},
		{Path: "/", AllowMask: int(ActionRead), Depth: 0},
	}
	if !Resolve(entries, "/a/b", ActionDelete) {
		t.Fatal("specific allow was not honoured")
	}
	if Resolve(entries, "/a/b", ActionWrite) {
		t.Fatal("write was granted but never allowed")
	}
}

func TestPermissionForEveryAction(t *testing.T) {
	for action, want := range map[Action]string{
		ActionRead:   PermRead,
		ActionWrite:  PermWrite,
		ActionDelete: PermDelete,
	} {
		got, err := PermissionFor(action)
		if err != nil || got != want {
			t.Fatalf("PermissionFor(%d) = %q, %v; want %q", int(action), got, err, want)
		}
	}
	if _, err := PermissionFor(Action(64)); err == nil {
		t.Fatal("unknown action did not error")
	}
}

func TestNormalizePath(t *testing.T) {
	cases := map[string]string{
		"":       "/",
		"/":      "/",
		"a":      "/a",
		"/a/":    "/a",
		"a//b/":  "/a/b",
		"//a///": "/a",
	}
	for in, want := range cases {
		if got := NormalizePath(in); got != want {
			t.Fatalf("NormalizePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPathDepth(t *testing.T) {
	cases := map[string]int{"/": 0, "/a": 1, "/a/b": 2}
	for in, want := range cases {
		if got := PathDepth(in); got != want {
			t.Fatalf("PathDepth(%q) = %d, want %d", in, got, want)
		}
	}
}
