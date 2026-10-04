package sqlenv

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/bigquery"
	"cloud.google.com/go/civil"
	"github.com/m-mizutani/goerr/v2"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

// insertBatch bounds how many rows one INSERT carries, so a statement stays a size the emulator
// parses quickly.
const insertBatch = 200

// DB is one emulator loaded with one scenario's tables. Every query only reads, so one DB serves
// every trial of the scenario.
type DB struct {
	client *bigquery.Client
	stop   func()
}

// Start runs a fresh emulator from image and loads tables into it. On a failure the container is
// removed.
func Start(ctx context.Context, image string, tables []*Table) (*DB, error) {
	endpoint, stop, err := startEmulator(ctx, image)
	if err != nil {
		return nil, err
	}
	client, err := bigquery.NewClient(ctx, Project, option.WithEndpoint(endpoint), option.WithoutAuthentication())
	if err != nil {
		stop()
		return nil, goerr.Wrap(err, "failed to connect to the BigQuery emulator", goerr.V("endpoint", endpoint))
	}
	db := &DB{client: client, stop: stop}
	if err := db.load(ctx, tables); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func (d *DB) load(ctx context.Context, tables []*Table) error {
	if err := d.client.Dataset(Dataset).Create(ctx, &bigquery.DatasetMetadata{}); err != nil {
		return goerr.Wrap(err, "failed to create the dataset", goerr.V("dataset", Dataset))
	}
	for _, t := range tables {
		if err := d.loadTable(ctx, t); err != nil {
			return err
		}
	}
	return nil
}

func (d *DB) loadTable(ctx context.Context, t *Table) error {
	schema, err := Schema(t)
	if err != nil {
		return err
	}
	cols := make([]string, 0, len(schema))
	for _, f := range schema {
		cols = append(cols, "`"+f.Name+"` "+typeOf(f))
	}
	if err := d.exec(ctx, fmt.Sprintf("CREATE TABLE `%s` (%s)", t.Qualified(), strings.Join(cols, ", "))); err != nil {
		return goerr.Wrap(err, "failed to create a table", goerr.V("table", t.Qualified()))
	}
	for start := 0; start < len(t.Rows); start += insertBatch {
		end := min(start+insertBatch, len(t.Rows))
		values := make([]string, 0, end-start)
		for _, row := range t.Rows[start:end] {
			columns := row.Data
			if !t.Flat {
				columns = map[string]any{columnID: row.ID, columnTimestamp: row.Timestamp,
					columnIngestedAt: row.Timestamp, columnData: row.Data}
			}
			lits := make([]string, 0, len(schema))
			for _, f := range schema {
				lit, err := literal(f, columns[f.Name])
				if err != nil {
					return goerr.Wrap(err, "a row cannot be written", goerr.V("table", t.Name), goerr.V("row_id", row.ID))
				}
				lits = append(lits, lit)
			}
			values = append(values, "("+strings.Join(lits, ", ")+")")
		}
		if err := d.exec(ctx, fmt.Sprintf("INSERT INTO `%s` VALUES %s", t.Qualified(), strings.Join(values, ", "))); err != nil {
			return goerr.Wrap(err, "failed to write rows", goerr.V("table", t.Qualified()), goerr.V("from_row", start))
		}
	}
	return nil
}

func (d *DB) exec(ctx context.Context, sql string) error {
	job, err := d.client.Query(sql).Run(ctx)
	if err != nil {
		return err
	}
	status, err := job.Wait(ctx)
	if err != nil {
		return err
	}
	return status.Err()
}

// Query runs one SELECT and returns up to MaxFetchRows rows, as JSON values, and how many rows the
// statement produced in all. Any other statement is refused without being run.
//
// Every trial of a scenario queries the same tables, so a statement that changed them would change
// the trials after it. A semicolon anywhere but at the end is refused, as it may start a second
// statement; this also refuses a string literal holding one, which the scenarios never need.
func (d *DB) Query(ctx context.Context, sql string) ([]map[string]any, int64, error) {
	if strings.Contains(strings.TrimRight(strings.TrimSpace(sql), "; \t\r\n"), ";") {
		return nil, 0, goerr.New("only one statement is run: remove every semicolon but a final one")
	}
	fields := strings.Fields(strings.TrimSpace(sql))
	first := ""
	if len(fields) > 0 {
		first = strings.ToUpper(fields[0])
	}
	if first != "SELECT" && first != "WITH" && !strings.HasPrefix(first, "(") {
		return nil, 0, goerr.New("only a SELECT statement is run", goerr.V("statement", first))
	}
	it, err := d.client.Query(sql).Read(ctx)
	if err != nil {
		return nil, 0, err
	}
	var rows []map[string]any
	for len(rows) < MaxFetchRows {
		var row map[string]bigquery.Value
		err := it.Next(&row)
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, 0, err
		}
		out := make(map[string]any, len(row))
		for k, v := range row {
			out[k] = convert(v)
		}
		rows = append(rows, out)
	}
	return rows, int64(it.TotalRows), nil // #nosec G115 -- a scenario's table holds a few thousand rows
}

// Close releases the client and removes the container.
func (d *DB) Close() error {
	err := d.client.Close()
	d.stop()
	if err != nil {
		return goerr.Wrap(err, "failed to close the BigQuery client")
	}
	return nil
}

// convert is a BigQuery value as encoding/json writes it: a TIMESTAMP in RFC 3339 UTC, a DATE or
// TIME as its text, a RECORD as a map and an array as a slice.
func convert(v bigquery.Value) any {
	switch x := v.(type) {
	case map[string]bigquery.Value:
		out := make(map[string]any, len(x))
		for k, item := range x {
			out[k] = convert(item)
		}
		return out
	case []bigquery.Value:
		out := make([]any, len(x))
		for i, item := range x {
			out[i] = convert(item)
		}
		return out
	case time.Time:
		return x.UTC().Format(time.RFC3339Nano)
	case civil.Date:
		return x.String()
	case civil.Time:
		return x.String()
	case civil.DateTime:
		return x.String()
	case []byte:
		return base64.StdEncoding.EncodeToString(x)
	case *big.Rat:
		return x.FloatString(9)
	}
	return v
}

func typeOf(f *bigquery.FieldSchema) string {
	t := scalarType(f)
	if f.Repeated {
		return "ARRAY<" + t + ">"
	}
	return t
}

func scalarType(f *bigquery.FieldSchema) string {
	switch f.Type {
	case bigquery.FloatFieldType:
		return "FLOAT64"
	case bigquery.BooleanFieldType:
		return "BOOL"
	case bigquery.TimestampFieldType:
		return "TIMESTAMP"
	case bigquery.RecordFieldType:
		parts := make([]string, 0, len(f.Schema))
		for _, sub := range f.Schema {
			parts = append(parts, "`"+sub.Name+"` "+typeOf(sub))
		}
		return "STRUCT<" + strings.Join(parts, ", ") + ">"
	}
	return "STRING"
}

// literal is one value of f as a typed GoogleSQL literal.
func literal(f *bigquery.FieldSchema, v any) (string, error) {
	if v == nil {
		return "CAST(NULL AS " + typeOf(f) + ")", nil
	}
	if f.Repeated {
		items, ok := v.([]any)
		if !ok {
			return "", goerr.New("a repeated column holds a value that is not a list", goerr.V("column", f.Name))
		}
		elem := *f
		elem.Repeated = false
		lits := make([]string, 0, len(items))
		for _, item := range items {
			// A BigQuery array cannot hold NULL.
			if item == nil {
				continue
			}
			lit, err := literal(&elem, item)
			if err != nil {
				return "", err
			}
			lits = append(lits, lit)
		}
		return "ARRAY<" + scalarType(f) + ">[" + strings.Join(lits, ", ") + "]", nil
	}
	switch f.Type {
	case bigquery.RecordFieldType:
		m, ok := v.(map[string]any)
		if !ok {
			return "", goerr.New("a record column holds a value that is not an object", goerr.V("column", f.Name))
		}
		lits := make([]string, 0, len(f.Schema))
		for _, sub := range f.Schema {
			lit, err := literal(sub, m[sub.Name])
			if err != nil {
				return "", err
			}
			lits = append(lits, lit)
		}
		return scalarType(f) + "(" + strings.Join(lits, ", ") + ")", nil
	case bigquery.TimestampFieldType:
		if t, ok := v.(time.Time); ok {
			return "TIMESTAMP " + quote(t.UTC().Format("2006-01-02 15:04:05.999999+00")), nil
		}
		return "CAST(" + quote(fmt.Sprint(v)) + " AS TIMESTAMP)", nil
	case bigquery.BooleanFieldType:
		if b, ok := v.(bool); ok && b {
			return "TRUE", nil
		}
		return "FALSE", nil
	case bigquery.FloatFieldType:
		n, ok := v.(float64)
		if !ok {
			return "", goerr.New("a FLOAT column holds a value that is not a number", goerr.V("column", f.Name))
		}
		if n == math.Trunc(n) && math.Abs(n) < 1e15 {
			return "CAST(" + strconv.FormatInt(int64(n), 10) + " AS FLOAT64)", nil
		}
		return "CAST(" + strconv.FormatFloat(n, 'g', -1, 64) + " AS FLOAT64)", nil
	}
	if s, ok := v.(string); ok {
		return quote(s), nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return "", goerr.Wrap(err, "a value cannot be encoded", goerr.V("column", f.Name))
	}
	return quote(string(raw)), nil
}

// quote writes a GoogleSQL string literal.
func quote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `'`, `\'`, "\n", `\n`, "\r", `\r`, "\t", `\t`)
	return "'" + r.Replace(s) + "'"
}
