package sqlenv

import (
	"fmt"
	"sort"

	"cloud.google.com/go/bigquery"
	"github.com/m-mizutani/goerr/v2"
)

// The columns of a log table besides its data record.
const (
	columnID         = "id"
	columnTimestamp  = "timestamp"
	columnIngestedAt = "ingested_at"
	columnData       = "data"
)

// Schema is the table's schema, inferred from its rows' values. A JSON number, whole or not, is
// FLOAT; a value that says nothing of its type (null, an empty object, an array of nulls) makes no
// column; two rows giving one column different types is an error.
func Schema(t *Table) (bigquery.Schema, error) {
	var data bigquery.Schema
	for _, row := range t.Rows {
		inferred, err := inferRecord(row.Data, "")
		if err != nil {
			return nil, goerr.Wrap(err, "a row holds a value the table cannot", goerr.V("table", t.Name), goerr.V("row_id", row.ID))
		}
		if data, err = mergeFields(data, inferred, ""); err != nil {
			return nil, goerr.Wrap(err, "a row's shape disagrees with an earlier row", goerr.V("table", t.Name), goerr.V("row_id", row.ID))
		}
	}
	if t.Flat {
		out := make(bigquery.Schema, 0, len(data))
		for _, f := range data {
			if f.Name == t.TimeColumn {
				copied := *f
				copied.Type = bigquery.TimestampFieldType
				f = &copied
			}
			out = append(out, f)
		}
		return out, nil
	}
	out := bigquery.Schema{
		{Name: columnID, Type: bigquery.StringFieldType},
		{Name: columnTimestamp, Type: bigquery.TimestampFieldType},
		{Name: columnIngestedAt, Type: bigquery.TimestampFieldType},
	}
	// A table with no rows has no data record: GoogleSQL cannot declare a STRUCT with no fields.
	if len(data) > 0 {
		out = append(out, &bigquery.FieldSchema{Name: columnData, Type: bigquery.RecordFieldType, Schema: data})
	}
	return out, nil
}

func joinPath(prefix, name string) string {
	if prefix == "" {
		return name
	}
	return prefix + "." + name
}

func inferRecord(m map[string]any, path string) (bigquery.Schema, error) {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	var out bigquery.Schema
	for _, name := range names {
		f, ok, err := inferField(name, m[name], joinPath(path, name))
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, f)
		}
	}
	return out, nil
}

func inferField(name string, v any, path string) (*bigquery.FieldSchema, bool, error) {
	switch x := v.(type) {
	case nil:
		return nil, false, nil
	case string:
		return &bigquery.FieldSchema{Name: name, Type: bigquery.StringFieldType}, true, nil
	case float64:
		return &bigquery.FieldSchema{Name: name, Type: bigquery.FloatFieldType}, true, nil
	case bool:
		return &bigquery.FieldSchema{Name: name, Type: bigquery.BooleanFieldType}, true, nil
	case map[string]any:
		nested, err := inferRecord(x, path)
		if err != nil || len(nested) == 0 {
			return nil, false, err
		}
		return &bigquery.FieldSchema{Name: name, Type: bigquery.RecordFieldType, Schema: nested}, true, nil
	case []any:
		var out *bigquery.FieldSchema
		for _, item := range x {
			f, ok, err := inferField(name, item, path)
			if err != nil {
				return nil, false, err
			}
			if !ok {
				continue
			}
			if out == nil {
				out = f
				continue
			}
			if out, err = mergeField(out, f, path); err != nil {
				return nil, false, err
			}
		}
		if out == nil {
			return nil, false, nil
		}
		out.Repeated = true
		return out, true, nil
	}
	// Whole numbers are written as float64, because a JSON number is FLOAT however it is written.
	return nil, false, goerr.New("a value of this Go type cannot be stored in a table",
		goerr.V("column", path), goerr.V("go_type", fmt.Sprintf("%T", v)))
}

func mergeFields(existing, addition bigquery.Schema, path string) (bigquery.Schema, error) {
	out := make(bigquery.Schema, 0, len(existing)+len(addition))
	index := map[string]int{}
	for i, f := range existing {
		copied := *f
		out = append(out, &copied)
		index[f.Name] = i
	}
	for _, f := range addition {
		i, ok := index[f.Name]
		if !ok {
			index[f.Name] = len(out)
			out = append(out, f)
			continue
		}
		merged, err := mergeField(out[i], f, joinPath(path, f.Name))
		if err != nil {
			return nil, err
		}
		out[i] = merged
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out, nil
}

func mergeField(existing, addition *bigquery.FieldSchema, path string) (*bigquery.FieldSchema, error) {
	if existing.Type != addition.Type || existing.Repeated != addition.Repeated {
		return nil, goerr.New("a column has two types", goerr.V("column", path),
			goerr.V("first", string(existing.Type)), goerr.V("then", string(addition.Type)),
			goerr.V("first_repeated", existing.Repeated), goerr.V("then_repeated", addition.Repeated))
	}
	if existing.Type != bigquery.RecordFieldType {
		return existing, nil
	}
	nested, err := mergeFields(existing.Schema, addition.Schema, path)
	if err != nil {
		return nil, err
	}
	merged := *existing
	merged.Schema = nested
	return &merged, nil
}

// Columns is what list_log_columns answers for the table: every leaf column by its dotted path and
// type, whether it repeats, and the arrays it sits inside, outermost first.
func Columns(t *Table) ([]map[string]any, error) {
	schema, err := Schema(t)
	if err != nil {
		return nil, err
	}
	var out []map[string]any
	var walk func(fields bigquery.Schema, prefix string, arrays []string)
	walk = func(fields bigquery.Schema, prefix string, arrays []string) {
		for _, f := range fields {
			path := joinPath(prefix, f.Name)
			if f.Type == bigquery.RecordFieldType {
				next := arrays
				if f.Repeated {
					next = append(append([]string(nil), arrays...), path)
				}
				walk(f.Schema, path, next)
				continue
			}
			entry := map[string]any{"column": path, "type": string(f.Type)}
			if f.Repeated {
				entry["repeated"] = true
			}
			if len(arrays) > 0 {
				unnest := make([]any, 0, len(arrays))
				for _, a := range arrays {
					unnest = append(unnest, a)
				}
				entry["unnest"] = unnest
			}
			out = append(out, entry)
		}
	}
	walk(schema, "", nil)
	return out, nil
}
