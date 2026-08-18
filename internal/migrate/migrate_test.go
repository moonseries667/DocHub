package migrate

import "testing"

func TestSplitStatementsDropsCommentsAndTrailingSemicolon(t *testing.T) {
	body := `-- a comment
CREATE TABLE a (id INT);

-- another comment
INSERT INTO a (id) VALUES (1);
`
	got := SplitStatements(body)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2: %#v", len(got), got)
	}
	if got[0] != "CREATE TABLE a (id INT)" {
		t.Fatalf("stmt 0 = %q", got[0])
	}
	if got[1] != "INSERT INTO a (id) VALUES (1)" {
		t.Fatalf("stmt 1 = %q", got[1])
	}
}

// A multi-line statement must survive: only the terminating line decides the cut.
func TestSplitStatementsKeepsMultiLineStatements(t *testing.T) {
	body := `INSERT INTO tenant (id, name)
VALUES (1, 'a'),
       (2, 'b');
`
	got := SplitStatements(body)
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1: %#v", len(got), got)
	}
}

func TestSplitStatementsTrailingStatementWithoutSemicolon(t *testing.T) {
	got := SplitStatements("SELECT 1")
	if len(got) != 1 || got[0] != "SELECT 1" {
		t.Fatalf("got = %#v", got)
	}
}
