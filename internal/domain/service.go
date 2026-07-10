package domain

type MappingStatus string

const (
	MappingExact      MappingStatus = "EXACT"
	MappingAmbiguous  MappingStatus = "AMBIGUOUS"
	MappingUnresolved MappingStatus = "UNRESOLVED"
)

type ServiceBinding struct {
	ID            string
	WorkspaceID   string
	ServiceID     string
	EnvironmentID string
	MappingStatus MappingStatus
}

func (binding ServiceBinding) CanExecute() bool {
	return binding.MappingStatus == MappingExact
}
