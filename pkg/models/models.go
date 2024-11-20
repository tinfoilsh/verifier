package models

type Measurements struct {
	PCR0 string
	PCR1 string
	PCR2 string
}

func (m *Measurements) Equals(other *Measurements) bool {
	return (m != nil && other != nil) && m.PCR0 == other.PCR0 && m.PCR1 == other.PCR1 && m.PCR2 == other.PCR2
}
