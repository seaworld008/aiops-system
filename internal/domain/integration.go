package domain

import "fmt"

type Integration struct {
	ID          string
	WorkspaceID string
	Provider    string
	Enabled     bool
}

func (integration Integration) Validate() error {
	if integration.ID == "" || integration.WorkspaceID == "" || integration.Provider == "" {
		return fmt.Errorf("integration id, workspace id and provider are required")
	}
	return nil
}
