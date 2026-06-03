package d1

import (
	"bytes"
	"context"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Driver implements database/sql/driver.Driver for Cloudflare D1 via Worker proxy.
type Driver struct{}

func (d *Driver) Open(name string) (driver.Conn, error) {
	// name is the proxy URL, e.g. "https://authspot.net"
	if name == "" {
		return nil, fmt.Errorf("d1: missing proxy URL")
	}
	name = strings.TrimRight(name, "/")
	return &conn{
		baseURL:    name,
		httpClient: &http.Client{Timeout: 300 * time.Second},
	}, nil
}

func init() {
	// Not auto-registered; the bootstrap code registers explicitly.
}

// conn implements driver.Conn, driver.ExecerContext, driver.QueryerContext.
type conn struct {
	baseURL    string
	httpClient *http.Client
}

func (c *conn) Prepare(query string) (driver.Stmt, error) {
	return &stmt{conn: c, query: query}, nil
}

func (c *conn) Close() error {
	return nil
}

func (c *conn) Begin() (driver.Tx, error) {
	// D1 doesn't support real transactions, but golang-migrate requires Begin().
	// Return a no-op tx; individual statements execute directly.
	return &noopTx{}, nil
}

// d1Request is the JSON body sent to the Worker proxy.
type d1Request struct {
	SQL    string `json:"sql"`
	Params []any  `json:"params,omitempty"`
}

// d1BatchRequest is one element of a batch request.
type d1BatchRequest struct {
	SQL    string `json:"sql"`
	Params []any  `json:"params,omitempty"`
}

// d1Response is the JSON response from the Worker proxy.
type d1Response struct {
	Success bool             `json:"success"`
	Error   string           `json:"error,omitempty"`
	Results []map[string]any `json:"results,omitempty"`
	Meta    *d1Meta          `json:"meta,omitempty"`
}

type d1BatchResponse struct {
	Success bool           `json:"success"`
	Error   string         `json:"error,omitempty"`
	Results []d1Response   `json:"results,omitempty"`
}

type d1Meta struct {
	Changes  int64 `json:"changes"`
	LastRowID int64 `json:"last_row_id"`
}

func (c *conn) doRequest(endpoint string, body any) (*d1Response, error) {
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("d1: failed to marshal request: %w", err)
	}

	url := c.baseURL + endpoint
	req, err := http.NewRequest("POST", url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("d1: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("d1: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("d1: failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("d1: HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var result d1Response
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("d1: failed to decode response: %w", err)
	}

	if !result.Success {
		return nil, fmt.Errorf("d1: %s", result.Error)
	}

	return &result, nil
}

func convertParams(args []driver.Value) []any {
	params := make([]any, len(args))
	for i, arg := range args {
		switch v := arg.(type) {
		case time.Time:
			params[i] = v.Unix()
		case []byte:
			// Convert bytes to array for D1
			arr := make([]int, len(v))
			for j, b := range v {
				arr[j] = int(b)
			}
			params[i] = arr
		case bool:
			if v {
				params[i] = 1
			} else {
				params[i] = 0
			}
		default:
			params[i] = v
		}
	}
	return params
}

func convertNamedParams(query string, args []driver.Value) (string, []any) {
	// D1 uses positional ? parameters. GORM may generate @p1, @p2 etc.
	// Convert @pN to ? and reorder args accordingly.
	re := regexp.MustCompile(`@p(\d+)`)
	matches := re.FindAllStringSubmatchIndex(query, -1)

	if len(matches) == 0 {
		// No named params, use args as-is
		return query, convertParams(args)
	}

	// Build new query with ? placeholders
	var result strings.Builder
	lastIdx := 0
	var newArgs []any
	seen := make(map[int]int) // param index -> position in newArgs

	for _, match := range matches {
		result.WriteString(query[lastIdx:match[0]])
		result.WriteString("?")

		paramIdx, _ := strconv.Atoi(query[match[2]:match[3]])
		// paramIdx is 1-based
		if pos, ok := seen[paramIdx]; ok {
			// Already seen, reference same position
			_ = pos
		} else {
			if paramIdx-1 < len(args) {
				newArgs = append(newArgs, convertParams([]driver.Value{args[paramIdx-1]})[0])
				seen[paramIdx] = len(newArgs) - 1
			} else {
				newArgs = append(newArgs, nil)
				seen[paramIdx] = len(newArgs) - 1
			}
		}

		lastIdx = match[1]
	}
	result.WriteString(query[lastIdx:])

	return result.String(), newArgs
}

// ExecerContext implements driver.ExecerContext.
func (c *conn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	// Convert NamedValue to Value
	values := make([]driver.Value, len(args))
	for i, arg := range args {
		values[i] = arg.Value
	}

	query, params := convertNamedParams(query, values)

	resp, err := c.doRequest("/__d1/exec", d1Request{
		SQL:    query,
		Params: params,
	})
	if err != nil {
		return nil, err
	}

	var changes, lastID int64
	if resp.Meta != nil {
		changes = resp.Meta.Changes
		lastID = resp.Meta.LastRowID
	}

	return &result{rowsAffected: changes, lastInsertId: lastID}, nil
}

// QueryerContext implements driver.QueryerContext.
func (c *conn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	values := make([]driver.Value, len(args))
	for i, arg := range args {
		values[i] = arg.Value
	}

	query, params := convertNamedParams(query, values)

	resp, err := c.doRequest("/__d1/query", d1Request{
		SQL:    query,
		Params: params,
	})
	if err != nil {
		return nil, err
	}

	if resp.Results == nil {
		return &rows{columns: []string{}, data: [][]any{}}, nil
	}

	// Extract columns from first result row
	var columns []string
	var data [][]any

	if len(resp.Results) > 0 {
		for col := range resp.Results[0] {
			columns = append(columns, col)
		}
		// Sort columns for consistent ordering
		// (Go map iteration is random)
		// We use the order from the first result
	}

	for _, row := range resp.Results {
		if columns == nil {
			for col := range row {
				columns = append(columns, col)
			}
		}
		values := make([]any, len(columns))
		for i, col := range columns {
			values[i] = row[col]
		}
		data = append(data, values)
	}

	return &rows{columns: columns, data: data}, nil
}

// stmt implements driver.Stmt.
type stmt struct {
	conn  *conn
	query string
}

func (s *stmt) Close() error { return nil }

func (s *stmt) NumInput() int {
	// Count ? placeholders
	return strings.Count(s.query, "?")
}

func (s *stmt) Exec(args []driver.Value) (driver.Result, error) {
	return s.conn.ExecContext(nil, s.query, valuesToNamed(args))
}

func (s *stmt) Query(args []driver.Value) (driver.Rows, error) {
	return s.conn.QueryContext(nil, s.query, valuesToNamed(args))
}

func valuesToNamed(args []driver.Value) []driver.NamedValue {
	named := make([]driver.NamedValue, len(args))
	for i, v := range args {
		named[i] = driver.NamedValue{
			Ordinal: i + 1,
			Value:   v,
		}
	}
	return named
}

// result implements driver.Result.
type result struct {
	lastInsertId int64
	rowsAffected int64
}

func (r *result) LastInsertId() (int64, error) {
	return r.lastInsertId, nil
}

func (r *result) RowsAffected() (int64, error) {
	return r.rowsAffected, nil
}

// rows implements driver.Rows.
type rows struct {
	columns []string
	data    [][]any
	pos     int
}

func (r *rows) Columns() []string {
	return r.columns
}

func (r *rows) Close() error {
	r.data = nil
	return nil
}

func (r *rows) Next(dest []driver.Value) error {
	if r.pos >= len(r.data) {
		return io.EOF
	}

	row := r.data[r.pos]
	r.pos++

	for i, v := range row {
		if i >= len(dest) {
			break
		}
		switch val := v.(type) {
		case float64:
			if val == float64(int64(val)) {
				dest[i] = int64(val)
			} else {
				dest[i] = val
			}
		case []interface{}:
			// D1 returns BLOB data as array of integers in JSON
			b := make([]byte, len(val))
			for j, item := range val {
				if f, ok := item.(float64); ok {
					b[j] = byte(f)
				}
			}
			dest[i] = b
		case nil:
			dest[i] = nil
		default:
			dest[i] = val
		}
	}

	return nil
}

// Ensure interfaces are satisfied.
var (
	_ driver.Driver        = (*Driver)(nil)
	_ driver.Conn          = (*conn)(nil)
	_ driver.ExecerContext  = (*conn)(nil)
	_ driver.QueryerContext = (*conn)(nil)
	_ driver.Stmt          = (*stmt)(nil)
	_ driver.Result        = (*result)(nil)
	_ driver.Rows          = (*rows)(nil)
)

// noopTx implements driver.Tx as a no-op for D1 (no real transaction support).
type noopTx struct{}

func (t *noopTx) Commit() error   { return nil }
func (t *noopTx) Rollback() error { return nil }
