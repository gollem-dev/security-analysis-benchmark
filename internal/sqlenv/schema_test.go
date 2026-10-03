package sqlenv_test

import (
	"testing"
	"time"

	"cloud.google.com/go/bigquery"
	"github.com/m-mizutani/gt"

	"github.com/gollem-dev/security-analysis-benchmark/internal/sqlenv"
)

var at = time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)

func names(s bigquery.Schema) []string {
	out := make([]string, 0, len(s))
	for _, f := range s {
		out = append(out, f.Name)
	}
	return out
}

func TestALogTableHasItsFourColumns(t *testing.T) {
	tb := &sqlenv.Table{Name: "logs", Rows: []sqlenv.Row{{ID: "1", Timestamp: at, Data: map[string]any{
		"n": 1.0, "ok": true, "who": map[string]any{"email": "a@example.com"}, "tags": []any{"x"}, "gone": nil,
		"events": []any{map[string]any{"name": "e", "parameters": []any{map[string]any{"name": "p"}}}},
	}}}}
	s, err := sqlenv.Schema(tb)
	gt.NoError(t, err).Required()
	gt.A(t, names(s)).Equal([]string{"id", "timestamp", "ingested_at", "data"})
	gt.V(t, s[1].Type).Equal(bigquery.TimestampFieldType)
	data := s[3].Schema
	gt.A(t, names(data)).Equal([]string{"events", "n", "ok", "tags", "who"})
	gt.V(t, data[1].Type).Equal(bigquery.FloatFieldType)
	gt.V(t, data[2].Type).Equal(bigquery.BooleanFieldType)
	gt.B(t, data[3].Repeated).True()
	gt.V(t, data[4].Type).Equal(bigquery.RecordFieldType)
	gt.B(t, data[0].Repeated).True()
}

func TestAnEmptyLogTableHasNoDataColumn(t *testing.T) {
	s, err := sqlenv.Schema(&sqlenv.Table{Name: "empty"})
	gt.NoError(t, err).Required()
	gt.A(t, names(s)).Equal([]string{"id", "timestamp", "ingested_at"})
}

func TestAFlatTableTypesItsTimeColumn(t *testing.T) {
	tb := &sqlenv.Table{Name: "f", Flat: true, TimeColumn: "ts", Rows: []sqlenv.Row{
		{ID: "1", Data: map[string]any{"ts": "2026-09-29T10:00:00Z", "user": "u"}},
		{ID: "2", Data: map[string]any{"ts": "2026-09-29T11:00:00Z", "count": 2.0}},
	}}
	s, err := sqlenv.Schema(tb)
	gt.NoError(t, err).Required()
	gt.A(t, names(s)).Equal([]string{"count", "ts", "user"})
	gt.V(t, s[1].Type).Equal(bigquery.TimestampFieldType)
}

func TestASchemaRefusesConflictsAndUnknownTypes(t *testing.T) {
	_, err := sqlenv.Schema(&sqlenv.Table{Name: "f", Flat: true, Rows: []sqlenv.Row{
		{ID: "1", Data: map[string]any{"v": "x"}}, {ID: "2", Data: map[string]any{"v": 1.0}}}})
	gt.Error(t, err)
	_, err = sqlenv.Schema(&sqlenv.Table{Name: "f", Flat: true, Rows: []sqlenv.Row{{ID: "1", Data: map[string]any{"v": 1}}}})
	gt.Error(t, err)
}

func TestColumnsNameTheArraysToUnnest(t *testing.T) {
	tb := &sqlenv.Table{Name: "logs", Rows: []sqlenv.Row{{ID: "1", Timestamp: at, Data: map[string]any{
		"events": []any{map[string]any{"name": "e", "parameters": []any{map[string]any{"name": "p", "value": "v"}}}},
	}}}}
	cols, err := sqlenv.Columns(tb)
	gt.NoError(t, err).Required()
	byPath := map[string]map[string]any{}
	for _, c := range cols {
		byPath[c["column"].(string)] = c
	}
	for _, path := range []string{"id", "timestamp", "ingested_at", "data.events.name", "data.events.parameters.name"} {
		_, ok := byPath[path]
		gt.B(t, ok).True()
	}
	gt.V(t, byPath["data.events.parameters.name"]["unnest"]).Equal([]any{"data.events", "data.events.parameters"})
	gt.V(t, byPath["data.events.name"]["unnest"]).Equal([]any{"data.events"})
	gt.V(t, byPath["timestamp"]["type"]).Equal("TIMESTAMP")
}
