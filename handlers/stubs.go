package handlers

import (
	"net/http"

	"github.com/jmoiron/sqlx"
)

// StubHandler provides placeholder endpoints for future implementation
type StubHandler struct {
	*BaseHandler
}

func NewStubHandler(database *sqlx.DB) *StubHandler {
	return &StubHandler{
		BaseHandler: NewBaseHandler(database),
	}
}

// NotImplemented returns a not implemented response
func (sh *StubHandler) NotImplemented(w http.ResponseWriter, r *http.Request) {
	WriteErrorResponse(w, http.StatusNotImplemented, "Endpoint not implemented", 
		"This endpoint is planned for future implementation")
}

// ComingSoon returns a coming soon response
func (sh *StubHandler) ComingSoon(w http.ResponseWriter, r *http.Request) {
	WriteJSONResponse(w, http.StatusOK, map[string]interface{}{
		"message": "Coming soon",
		"status":  "planned",
		"endpoint": r.URL.Path,
	})
}
