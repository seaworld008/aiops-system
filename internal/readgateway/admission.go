package readgateway

import (
	"encoding/json"
	"fmt"
	"io"
)

type admissionSeal struct{ value byte }

var trustedAdmissionSeal = &admissionSeal{value: 1}

// Admission is the process-owned READ lease progression gate. The production
// package deliberately exposes only the closed constructor; opening claims is
// a separate Go/No-Go decision and cannot be selected through configuration.
type Admission struct {
	closed bool
	seal   *admissionSeal
	self   *Admission
}

// NewClosedAdmission returns the only admission state available to runtime
// assembly in this milestone. A copied or decoded value remains fail closed.
func NewClosedAdmission() *Admission {
	admission := &Admission{closed: true, seal: trustedAdmissionSeal}
	admission.self = admission
	return admission
}

func (admission *Admission) valid() bool {
	return admission != nil && admission.self == admission && admission.seal == trustedAdmissionSeal
}

func (admission *Admission) allowsLeaseProgression() bool {
	return admission.valid() && !admission.closed
}

func (Admission) String() string   { return "<aiops-read-admission>" }
func (Admission) GoString() string { return "<aiops-read-admission>" }
func (Admission) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "<aiops-read-admission>")
}
func (Admission) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func (*Admission) UnmarshalJSON([]byte) error  { return ErrInvalidConfiguration }

var _ json.Marshaler = Admission{}
