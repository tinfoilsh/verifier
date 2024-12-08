package models

import (
	"encoding/hex"
	"fmt"

	"github.com/blocky/nitrite"
)

type Measurements struct {
	PCR0 string
	PCR1 string
	PCR2 string
}

func (m *Measurements) Equals(other *Measurements) bool {
	return (m != nil && other != nil) && m.PCR0 == other.PCR0 && m.PCR1 == other.PCR1 && m.PCR2 == other.PCR2
}

func (m *Measurements) String() string {
	return fmt.Sprintf(`{"PCR0":"%s", "PCR1":"%s", "PCR2":"%s"}`, m.PCR0, m.PCR1, m.PCR2)
}

func MeasurementFromDoc(doc *nitrite.Document) *Measurements {
	return &Measurements{
		PCR0: hex.EncodeToString(doc.PCRs[0]),
		PCR1: hex.EncodeToString(doc.PCRs[1]),
		PCR2: hex.EncodeToString(doc.PCRs[2]),
	}
}
