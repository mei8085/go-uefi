package signature

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// buildWINCert builds a raw WIN_CERTIFICATE with the given length field,
// revision, type and payload.
func buildWINCert(length uint32, revision uint16, ctype WINCertType, payload []byte) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, length)
	_ = binary.Write(&b, binary.LittleEndian, revision)
	_ = binary.Write(&b, binary.LittleEndian, ctype)
	b.Write(payload)
	return b.Bytes()
}

func TestReadWinCertificateRejectsOversizedLength(t *testing.T) {
	payload := []byte{0xAA, 0xBB, 0xCC}
	// Declare more data than the buffer actually holds.
	blob := buildWINCert(8+uint32(len(payload))+16, WIN_CERTIFICATE_REVISION, WIN_CERT_TYPE_PKCS_SIGNED_DATA, payload)

	if _, err := ReadWinCertificate(bytes.NewReader(blob)); !errors.Is(err, ErrCertificateTableLength) {
		t.Fatalf("expected ErrCertificateTableLength, got: %v", err)
	}
}

func TestReadWinCertificateRejectsLengthBelowHeader(t *testing.T) {
	blob := buildWINCert(4, WIN_CERTIFICATE_REVISION, WIN_CERT_TYPE_PKCS_SIGNED_DATA, nil)
	if _, err := ReadWinCertificate(bytes.NewReader(blob)); !errors.Is(err, ErrCertificateTableLength) {
		t.Fatalf("expected ErrCertificateTableLength, got: %v", err)
	}
}

func TestReadWinCertificateRejectsBadRevision(t *testing.T) {
	payload := []byte{0x01}
	blob := buildWINCert(8+uint32(len(payload)), 0x0100, WIN_CERT_TYPE_PKCS_SIGNED_DATA, payload)
	if _, err := ReadWinCertificate(bytes.NewReader(blob)); err == nil {
		t.Fatalf("expected bad revision to be rejected")
	}
}

func TestReadWinCertificateAcceptsValidEntry(t *testing.T) {
	payload := make([]byte, 32)
	for i := range payload {
		payload[i] = byte(i)
	}
	blob := buildWINCert(8+uint32(len(payload)), WIN_CERTIFICATE_REVISION, WIN_CERT_TYPE_PKCS_SIGNED_DATA, payload)

	cert, err := ReadWinCertificate(bytes.NewReader(blob))
	if err != nil {
		t.Fatalf("valid entry rejected: %v", err)
	}
	if cert.Length != 8+uint32(len(payload)) {
		t.Fatalf("unexpected length: %d", cert.Length)
	}
	if !bytes.Equal(cert.Certificate, payload) {
		t.Fatalf("payload mismatch")
	}
}

func TestReadWinCertificateUEFIGUIDRejectsTruncatedGUID(t *testing.T) {
	// A UEFI GUID entry needs at least 16 bytes of certificate data.
	payload := []byte{0x01, 0x02, 0x03}
	blob := buildWINCert(8+uint32(len(payload)), WIN_CERTIFICATE_REVISION, WIN_CERT_TYPE_EFI_GUID, payload)
	if _, err := ReadWinCertificateUEFIGUID(bytes.NewReader(blob)); !errors.Is(err, ErrCertificateTableLength) {
		t.Fatalf("expected ErrCertificateTableLength, got: %v", err)
	}
}

func TestReadEFIVariableAuthentication2RejectsWrongCertType(t *testing.T) {
	// Build a time prefix plus a WIN_CERTIFICATE with the wrong outer type.
	var b bytes.Buffer
	// EFITime is 16 bytes in this library.
	b.Write(make([]byte, 16))
	payload := make([]byte, 16+8) // GUID + some data
	hdr := buildWINCert(8+uint32(len(payload)), WIN_CERTIFICATE_REVISION, WIN_CERT_TYPE_PKCS_SIGNED_DATA, payload)
	b.Write(hdr)

	if _, err := ReadEFIVariableAuthencation2(bytes.NewReader(b.Bytes())); !errors.Is(err, ErrCertificateType) {
		t.Fatalf("expected ErrCertificateType, got: %v", err)
	}
}
