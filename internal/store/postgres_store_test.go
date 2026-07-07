package store

import "testing"

func TestBindPostgresPlaceholders(t *testing.T) {
	query := bindPlaceholders(dialectPostgres, "insert into reports(id, summary) values(?, ?) where id = ?")

	want := "insert into reports(id, summary) values($1, $2) where id = $3"
	if query != want {
		t.Fatalf("expected %q, got %q", want, query)
	}
}

func TestBindSQLiteLeavesQuestionMarks(t *testing.T) {
	query := bindPlaceholders(dialectSQLite, "insert into reports(id, summary) values(?, ?)")

	want := "insert into reports(id, summary) values(?, ?)"
	if query != want {
		t.Fatalf("expected %q, got %q", want, query)
	}
}
