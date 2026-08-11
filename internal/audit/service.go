package audit

import (
	"context"
	"database/sql"
	"encoding/json"

	"goleanauth/internal/apperror"
)

type AuditService struct {
	DB *sql.DB
}

func NewAuditService(dbConn *sql.DB) *AuditService {
	return &AuditService{
		DB: dbConn,
	}
}

// Log logs an audit log
func (s *AuditService) Log(ctx context.Context, tx *sql.Tx, entry LogEntry) error {
	metadata, err := json.Marshal(entry.Metadata)
	if err != nil {
		return apperror.ErrInternalServer
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO audit_logs (
			user_id, 
			action,
			metadata,
			entity_type, 
			entity_id, 
			ip_address, 
			user_agent
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, entry.UserID, entry.Action, string(metadata), entry.EntityType, entry.EntityID, entry.ipAddress, entry.userAgent)
	if err != nil {
		return apperror.ErrDatabase
	}

	return nil
}
