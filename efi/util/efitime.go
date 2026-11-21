package util

import (
	"fmt"
	"time"
)

// Section 8.2 - Time Services

var (
	EFI_TIME_ADJUST_DAYLIGHT uint8  = 0x01
	EFI_TIME_IN_DAYLIGHT     uint8  = 0x02
	EFI_UNSPECIFIED_TIMEZONE uint16 = 0x07FF
)

const SizeofEFITime = 2 + 6 + 4 + 2 + 2

type EFITime struct {
	Year       uint16 // 1900 - 9999 AKA Y99K y'all
	Month      uint8  // 1-12
	Day        uint8  // 1 -31
	Hour       uint8  // 0 - 23
	Minute     uint8  // 0 - 59
	Second     uint8  // 0 - 59
	Pad1       uint8
	Nanosecond uint32 // 0 - 999,999,999
	TimeZone   int16  // -1440 to 1440 or 2047
	Daylight   uint8
	Pad2       uint8
}

func (e *EFITime) Format() string {
	return fmt.Sprintf("%d-%d-%d %d:%d:%d:%d", e.Year, e.Month, e.Day, e.Hour, e.Minute, e.Second, e.Nanosecond)
}

// Compare compares two EFITime timestamps by their wall-clock fields. The
// Pad, TimeZone and Daylight fields are ignored. It returns -1 if e is
// before o, 0 if they are equal and 1 if e is after o.
func (e EFITime) Compare(o EFITime) int {
	fields := func(t EFITime) []uint64 {
		return []uint64{
			uint64(t.Year), uint64(t.Month), uint64(t.Day),
			uint64(t.Hour), uint64(t.Minute), uint64(t.Second),
			uint64(t.Nanosecond),
		}
	}
	a, b := fields(e), fields(o)
	for i := range a {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

// Before returns true if e is strictly before o.
func (e EFITime) Before(o EFITime) bool {
	return e.Compare(o) < 0
}

// After returns true if e is strictly after o.
func (e EFITime) After(o EFITime) bool {
	return e.Compare(o) > 0
}

type EFITImeCapabilitie struct {
	Resolution uint32
	Accuracy   uint32
	SetsToZero bool
}

func NewEFITime() *EFITime {
	t := time.Now()
	return &EFITime{
		Year:   uint16(t.Year()),
		Month:  uint8(t.Month()),
		Day:    uint8(t.Day()),
		Hour:   uint8(t.Hour()),
		Minute: uint8(t.Minute()),
		Second: uint8(t.Second()),
	}
}
