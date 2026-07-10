package domain

type ActorType string

const (
	ActorHuman    ActorType = "HUMAN"
	ActorModel    ActorType = "MODEL"
	ActorWorkload ActorType = "WORKLOAD"
)

type Actor struct {
	Type ActorType
	ID   string
}
