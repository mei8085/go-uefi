package authenticode

import (
	"bytes"
	"crypto/x509"
	"debug/pe"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/foxboron/go-uefi/internal/certtest"
)

// signedPE is a test.pecoff image together with a valid Authenticode
// signature appended the same way AppendSignature does it.
type signedPE struct {
	image    []byte
	tableOff uint32 // file offset of the certificate table
}

// signTestPE signs test.pecoff and returns the raw bytes plus table metadata.
func signTestPE(t *testing.T) (*signedPE, *x509.Certificate) {
	t.Helper()
	cert, key := certtest.MkCert(t)

	p, err := Parse(bytes.NewReader(mustOpen("testdata/test.pecoff")))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := p.Sign(key, cert); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return &signedPE{
		image:    p.Bytes(),
		tableOff: p.Datadir.VirtualAddress,
	}, cert
}

// dataDirectoryOffset returns the file offset of the Certificate Table data
// directory entry (index 4, 8 bytes: VirtualAddress + Size).
func dataDirectoryOffset(t *testing.T, b []byte) int64 {
	t.Helper()
	f, err := pe.NewFile(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("pe.NewFile: %v", err)
	}
	defer f.Close()

	// Locate the optional header data directory table. debug/pe parses it but
	// does not expose offsets, so recompute them from the DOS/COFF headers.
	peOff := int64(binary.LittleEndian.Uint32(b[0x3c:]))
	coff := peOff + 4 // skip "PE\0\0"
	optOff := coff + 20
	magic := binary.LittleEndian.Uint16(b[optOff:])
	var ddOff int64
	switch magic {
	case 0x10b: // PE32
		ddOff = optOff + 96
	case 0x20b: // PE32+
		ddOff = optOff + 112
	default:
		t.Fatalf("unknown optional header magic 0x%x", magic)
	}
	// Entry 4 starts at ddOff + 4*8.
	return ddOff + 4*8
}

// setDataDirectory overwrites the VirtualAddress and Size fields of data
// directory entry 4.
func setDataDirectory(t *testing.T, b []byte, va, size uint32) []byte {
	t.Helper()
	out := bytes.Clone(b)
	off := dataDirectoryOffset(t, out)
	binary.LittleEndian.PutUint32(out[off:], va)
	binary.LittleEndian.PutUint32(out[off+4:], size)
	return out
}

// setWINCertLength overwrites the dwLength field of the first WIN_CERTIFICATE.
func setWINCertLength(b []byte, tableOff uint32, length uint32) []byte {
	out := bytes.Clone(b)
	binary.LittleEndian.PutUint32(out[tableOff:], length)
	return out
}

// setWINCertType overwrites the wCertificateType field of the first entry.
func setWINCertType(b []byte, tableOff uint32, ctype uint16) []byte {
	out := bytes.Clone(b)
	binary.LittleEndian.PutUint16(out[tableOff+6:], ctype)
	return out
}

// assertRejected parses (or verifies) the image and requires a recognizable
// failure. A forged image must never validate, and malformed tables must
// surface ErrCertificateTable rather than being silently accepted.
func assertRejected(t *testing.T, b []byte, trusted *x509.Certificate) {
	t.Helper()
	p, err := Parse(bytes.NewReader(b))
	if err == nil {
		// If parsing succeeds, verification must still refuse the image.
		ok, verr := p.Verify(trusted)
		if verr == nil && ok {
			t.Fatalf("forged image was accepted as valid (ok=true)")
		}
		return
	}
	if !errors.Is(err, ErrCertificateTable) {
		t.Fatalf("expected ErrCertificateTable, got: %v", err)
	}
}

func TestCertificateTableTrailingUnsignedData(t *testing.T) {
	s, trusted := signTestPE(t)

	// Append arbitrary unsigned bytes after the table without updating the
	// declared size. The bytes are outside both the image hash and every
	// WIN_CERTIFICATE, so they must not be accepted.
	forged := bytes.Clone(s.image)
	forged = append(forged, 0xDE, 0xAD, 0xBE, 0xEF)

	p, err := Parse(bytes.NewReader(forged))
	if err == nil {
		// Some layouts let Parse succeed; Verify must then fail closed.
		ok, verr := p.Verify(trusted)
		if verr == nil && ok {
			t.Fatalf("trailing unsigned data after the table was accepted")
		}
		return
	}
	if !errors.Is(err, ErrCertificateTable) {
		t.Fatalf("expected ErrCertificateTable for trailing data, got: %v", err)
	}
}

func TestCertificateTableDeclaredSizeOvershoot(t *testing.T) {
	s, trusted := signTestPE(t)

	// Inflate the declared table size beyond end of file. The declared bounds
	// no longer match the image, which must be rejected.
	forged := setDataDirectory(t, s.image, s.tableOff, uint32(len(s.image))-s.tableOff+64)
	assertRejected(t, forged, trusted)
}

func TestCertificateTableDeclaredSizeUndershoot(t *testing.T) {
	s, trusted := signTestPE(t)

	// Shrink the declared size so part of the real table (and any padding)
	// falls outside the declared certificate table.
	realSize := uint32(len(s.image)) - s.tableOff
	forged := setDataDirectory(t, s.image, s.tableOff, realSize-8)
	assertRejected(t, forged, trusted)
}

func TestWINCertificateOversizedLength(t *testing.T) {
	s, trusted := signTestPE(t)

	// Claim the single WIN_CERTIFICATE is longer than the whole table.
	entryHdr := binary.LittleEndian.Uint32(s.image[s.tableOff:])
	forged := setWINCertLength(s.image, s.tableOff, entryHdr+128)
	assertRejected(t, forged, trusted)
}

func TestWINCertificateUndersizedLength(t *testing.T) {
	s, trusted := signTestPE(t)

	// dwLength smaller than the 8 byte header is always invalid.
	forged := setWINCertLength(s.image, s.tableOff, 4)
	assertRejected(t, forged, trusted)
}

func TestWINCertificateNonZeroPadding(t *testing.T) {
	s, trusted := signTestPE(t)

	entryLen := binary.LittleEndian.Uint32(s.image[s.tableOff:])
	// The real sbsign-style layout pads the entry up to an 8-byte boundary.
	padOff := s.tableOff + entryLen
	if padOff >= uint32(len(s.image)) {
		t.Skip("entry has no alignment padding to corrupt")
	}
	forged := bytes.Clone(s.image)
	forged[padOff] = 0x01 // padding must be zeroes
	assertRejected(t, forged, trusted)
}

func TestWINCertificateUnknownType(t *testing.T) {
	s, trusted := signTestPE(t)

	// An unrecognised certificate type is unsigned structural data.
	forged := setWINCertType(s.image, s.tableOff, 0x0099)
	assertRejected(t, forged, trusted)
}

func TestTableWalkerRejectsMalformedSecondEntry(t *testing.T) {
	s, trusted := signTestPE(t)

	// Build a table with two entries: the first fully valid, the second
	// malformed. A parser that walks entries loosely (or stops after the first
	// valid signature) would ignore the corrupt second entry and still report
	// success. The strict walker must reject the table instead.
	entryLen := binary.LittleEndian.Uint32(s.image[s.tableOff:])
	aligned := (int64(entryLen) + 7) &^ 7
	entry := s.image[s.tableOff : s.tableOff+uint32(aligned)]

	var bld bytes.Buffer
	bld.Write(s.image[:s.tableOff])
	bld.Write(entry)
	second := bytes.Clone(entry)
	// Corrupt the second entry's declared length so it overshoots the table.
	binary.LittleEndian.PutUint32(second, uint32(len(entry))+64)
	bld.Write(second)
	forged := bld.Bytes()

	// Declare the table to cover both aligned entries.
	forged = setDataDirectory(t, forged, s.tableOff, uint32(2*aligned))

	p, err := Parse(bytes.NewReader(forged))
	if err != nil {
		if !errors.Is(err, ErrCertificateTable) {
			t.Fatalf("expected ErrCertificateTable, got: %v", err)
		}
		return
	}
	// Parsing may defer the walk to Signatures(); it must fail there too.
	if _, err := p.Signatures(); !errors.Is(err, ErrCertificateTable) {
		t.Fatalf("expected Signatures to return ErrCertificateTable, got: %v", err)
	}
	// And Verify must never report success over a table it cannot fully walk.
	if ok, _ := p.Verify(trusted); ok {
		t.Fatalf("Verify accepted a table containing a malformed second entry")
	}
}

// Sanity check: the unmodified, properly signed image still verifies.
func TestProperlySignedImageStillVerifies(t *testing.T) {
	s, trusted := signTestPE(t)
	p, err := Parse(bytes.NewReader(s.image))
	if err != nil {
		t.Fatalf("Parse of valid image failed: %v", err)
	}
	ok, err := p.Verify(trusted)
	if err != nil || !ok {
		t.Fatalf("valid signature rejected: ok=%v err=%v", ok, err)
	}
}
