package audit

type LogEntry struct {
	UserID     *string
	Action     string
	EntityType string
	EntityID   *string
	ipAddress  string
	userAgent  string
	Metadata   map[string]any
}
