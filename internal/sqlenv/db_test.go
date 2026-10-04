package sqlenv_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/m-mizutani/gt"

	"github.com/gollem-dev/security-analysis-benchmark/internal/sqlenv"
)

// The emulator runs in Docker. Without Docker these tests fail rather than skip: the SQL scenarios
// cannot be checked any other way.
func TestTheEmulatorRunsBigQuerySQL(t *testing.T) {
	ctx := context.Background()
	logs := &sqlenv.Table{Name: "logs", Description: "Log rows."}
	for i := range 3 {
		logs.Rows = append(logs.Rows, sqlenv.Row{ID: fmt.Sprintf("r%d", i), Timestamp: at.Add(time.Duration(i) * time.Hour),
			Data: map[string]any{"actor": map[string]any{"email": "alice@example.com"},
				"events": []any{map[string]any{"name": "download", "parameters": []any{
					map[string]any{"name": "doc_id", "value": fmt.Sprintf("d%d", i)}}}}}})
	}
	big := &sqlenv.Table{Name: "big", Flat: true, TimeColumn: "ts"}
	for i := range 1500 {
		big.Rows = append(big.Rows, sqlenv.Row{ID: fmt.Sprint(i), Data: map[string]any{"ts": "2026-09-29T00:00:00Z", "n": float64(i)}})
	}
	db, err := sqlenv.Start(ctx, sqlenv.DefaultImage, []*sqlenv.Table{logs, big})
	gt.NoError(t, err).Required()
	t.Cleanup(func() { _ = db.Close() })

	rows, matched, err := db.Query(ctx, "SELECT p.value AS doc FROM `"+logs.Qualified()+"` AS t, UNNEST(t.data.events) AS e, "+
		"UNNEST(e.parameters) AS p WHERE e.name = 'download' AND t.timestamp >= TIMESTAMP('2026-09-29T11:00:00Z') ORDER BY 1")
	gt.NoError(t, err).Required()
	gt.N(t, matched).Equal(int64(2))
	gt.V(t, rows).Equal([]map[string]any{{"doc": "d1"}, {"doc": "d2"}})

	rows, matched, err = db.Query(ctx, "SELECT n FROM `"+big.Qualified()+"`")
	gt.NoError(t, err).Required()
	gt.A(t, rows).Length(sqlenv.MaxFetchRows)
	gt.N(t, matched).Equal(int64(1500))

	_, _, err = db.Query(ctx, "DELETE FROM `"+big.Qualified()+"` WHERE TRUE")
	gt.Error(t, err)
	_, _, err = db.Query(ctx, "SELECT nope FROM `"+big.Qualified()+"`")
	gt.Error(t, err)

	// A second statement after a SELECT is refused, and the table keeps its rows.
	_, _, err = db.Query(ctx, "SELECT 1; DELETE FROM `"+big.Qualified()+"` WHERE TRUE")
	gt.Error(t, err)
	_, matched, err = db.Query(ctx, "SELECT n FROM `"+big.Qualified()+"`;")
	gt.NoError(t, err).Required()
	gt.N(t, matched).Equal(int64(1500))
}
