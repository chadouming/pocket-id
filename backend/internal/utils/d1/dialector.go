package d1

import (
	"database/sql"
	"fmt"

	"gorm.io/gorm"
	"gorm.io/gorm/callbacks"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/schema"
)

// Dialector implements gorm.Dialector for Cloudflare D1.
type Dialector struct {
	DSN string
}

func Open(dsn string) gorm.Dialector {
	return &Dialector{DSN: dsn}
}

func (d *Dialector) Name() string {
	return "d1"
}

func (d *Dialector) Initialize(db *gorm.DB) error {
	// Register the D1 driver
	sqlDB, err := sql.Open("d1", d.DSN)
	if err != nil {
		return fmt.Errorf("d1: failed to open database: %w", err)
	}

	db.ConnPool = sqlDB

	// Register SQLite-compatible callbacks
	callbacks.RegisterDefaultCallbacks(db, &callbacks.Config{
		CreateClauses: []string{"INSERT", "VALUES", "ON CONFLICT", "RETURNING"},
		QueryClauses:  []string{"SELECT", "FROM", "WHERE", "GROUP BY", "ORDER BY", "LIMIT", "FOR"},
		UpdateClauses: []string{"UPDATE", "SET", "WHERE", "RETURNING"},
		DeleteClauses: []string{"DELETE", "FROM", "WHERE", "RETURNING"},
	})

	return nil
}

func (d *Dialector) Migrator(db *gorm.DB) gorm.Migrator {
	return nil
}

func (d *Dialector) DataTypeOf(field *schema.Field) string {
	switch field.DataType {
	case schema.Bool:
		return "numeric"
	case schema.Int, schema.Uint:
		return "integer"
	case schema.Float:
		return "real"
	case schema.String:
		return "text"
	case schema.Time:
		return "numeric"
	case schema.Bytes:
		return "blob"
	default:
		return "text"
	}
}

func (d *Dialector) DefaultValueOf(field *schema.Field) clause.Expression {
	return clause.Expr{SQL: "DEFAULT"}
}

func (d *Dialector) BindVarTo(writer clause.Writer, stmt *gorm.Statement, v interface{}) {
	writer.WriteByte('?')
}

func (d *Dialector) QuoteTo(writer clause.Writer, str string) {
	writer.WriteByte('`')
	writer.WriteString(str)
	writer.WriteByte('`')
}

func (d *Dialector) Explain(sql string, vars ...interface{}) string {
	return fmt.Sprintf(sql, vars...)
}
