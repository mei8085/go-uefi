package signature

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/binary"
	"io"
	"log"

	"github.com/pkg/errors"
	"golang.org/x/crypto/cryptobyte"

	"github.com/foxboron/go-uefi/efi/util"
	"github.com/foxboron/go-uefi/efivar"
	"github.com/foxboron/go-uefi/pkcs7"
)

// Section 32.2.4 Code Defintiions
// Page. 1707
// WIN_CERTIFICATE_UEFI_GUID

// According to page 1705
// UEFI Spec February 2020
var WIN_CERTIFICATE_REVISION uint16 = 0x0200

type WINCertType uint16

// Page 1705
// 0x0EF0 to 0x0EFF is the reserved range
var (
	WIN_CERT_TYPE_PKCS_SIGNED_DATA WINCertType = 0x0002
	WIN_CERT_TYPE_EFI_PKCS1_15     WINCertType = 0x0EF0
	WIN_CERT_TYPE_EFI_GUID         WINCertType = 0x0EF1
)

var WINCertTypeString = map[WINCertType]string{
	0x0002: "WIN_CERT_TYPE_PKCS_SIGNED_DATA",
	0x0EF0: "WIN_CERT_TYPE_EFI_PKCS1_15",
	0x0EF1: "WIN_CERT_TYPE_EFI_GUID",
}

// PE/COFF structure for signing
// Page 1705
type WINCertificate struct {
	Length      uint32
	Revision    uint16
	CertType    WINCertType
	Certificate []uint8
}

const SizeofWINCertificate = 4 + 2 + 2

var (
	ErrParse = errors.New("could not parse struct")

	// ErrCertificateTableLength is returned when a WIN_CERTIFICATE entry
	// declares a length that does not fit inside the certificate table (or
	// reader) it is part of. Such an entry can be used to smuggle bytes past
	// the parser while still producing a superficially valid structure.
	ErrCertificateTableLength = errors.New("WIN_CERTIFICATE length exceeds certificate table bounds")

	// ErrCertificateType is returned when a WIN_CERTIFICATE entry uses a
	// certificate type that is not recognised.
	ErrCertificateType = errors.New("unknown WIN_CERTIFICATE certificate type")
)

// ReadWinCertificate reads a single WIN_CERTIFICATE structure from f.
//
// The PE/COFF and UEFI specifications require the dwLength field to cover the
// entire structure (the 8 byte header plus the bCertificate data) and to be
// 8-byte aligned inside the Attribute Certificate Table. The length is
// validated against the remaining bytes of f so a forged, oversized length can
// never cause an out-of-bounds read or silently consume unrelated data.
func ReadWinCertificate(f io.Reader) (WINCertificate, error) {
	var cert WINCertificate
	for _, v := range []interface{}{&cert.Length, &cert.Revision, &cert.CertType} {
		if err := binary.Read(f, binary.LittleEndian, v); err != nil {
			return WINCertificate{}, errors.Wrapf(err, "could not parse WINCertificate")
		}
	}
	if cert.Revision != WIN_CERTIFICATE_REVISION {
		return WINCertificate{}, errors.Wrapf(ErrParse, "WINCertificate revision should be %x, but is %x. Malformed or invalid", WIN_CERTIFICATE_REVISION, cert.Revision)
	}

	// The length must at least cover the fixed header and must not overflow.
	if cert.Length < SizeofWINCertificate {
		return WINCertificate{}, errors.Wrapf(ErrCertificateTableLength, "WIN_CERTIFICATE length %d is smaller than the %d byte header", cert.Length, SizeofWINCertificate)
	}

	certLen := int64(cert.Length) - SizeofWINCertificate

	// Bound the declared length against the data that is actually available.
	// A bytes.Reader (the normal caller) reports its remaining bytes through
	// Len(); any other reader is trusted to return io.EOF once exhausted.
	var remaining int64 = -1
	if l, ok := f.(interface{ Len() int }); ok {
		remaining = int64(l.Len())
	}
	if remaining >= 0 && certLen > remaining {
		return WINCertificate{}, errors.Wrapf(ErrCertificateTableLength, "WIN_CERTIFICATE declares %d certificate bytes but only %d bytes remain in the certificate table", certLen, remaining)
	}

	certLength := make([]byte, certLen)
	if _, err := io.ReadFull(f, certLength); err != nil {
		return WINCertificate{}, errors.Wrapf(ErrCertificateTableLength, "could not read %d bytes of WIN_CERTIFICATE data: %v", certLen, err)
	}
	cert.Certificate = certLength[:]
	return cert, nil
}

func WriteWinCertificate(b io.Writer, w *WINCertificate) {
	for _, d := range []interface{}{w.Length, w.Revision, w.CertType, w.Certificate} {
		if err := binary.Write(b, binary.LittleEndian, d); err != nil {
			log.Fatal(err)
		}
	}
}

var (
	EFI_CERT_TYPE_RSA2048_SHA256_GUID = util.EFIGUID{0xa7717414, 0xc616, 0x4977, [8]uint8{0x94, 0x20, 0x84, 0x47, 0x12, 0xa7, 0x35, 0xbf}}
	EFI_CERT_TYPE_PKCS7_GUID          = util.EFIGUID{0x4aafd29d, 0x68df, 0x49ee, [8]uint8{0x8a, 0xa9, 0x34, 0x7d, 0x37, 0x56, 0x65, 0xa7}}
)

// Should implement an interface
// Page 1707
type WinCertificateUEFIGUID struct {
	Header   WINCertificate
	CertType util.EFIGUID // One of the EFI_CERT types
	CertData []uint8
}

const SizeofWinCertificateUEFIGUID = SizeofWINCertificate + util.SizeofEFIGUID

func ReadWinCertificateUEFIGUID(f io.Reader) (WinCertificateUEFIGUID, error) {
	var cert WinCertificateUEFIGUID
	hdr, err := ReadWinCertificate(f)
	if err != nil {
		return WinCertificateUEFIGUID{}, errors.Wrap(err, "could not parse WINCert UEFI_GUID")
	}
	cert.Header = hdr

	// The remaining certificate bytes must contain exactly one EFI GUID and
	// the opaque certificate data. A short buffer means a truncated entry.
	if uint32(len(hdr.Certificate)) < util.SizeofEFIGUID {
		return WinCertificateUEFIGUID{}, errors.Wrapf(ErrCertificateTableLength, "WIN_CERTIFICATE_UEFI_GUID has %d certificate bytes, need at least %d for the GUID", len(hdr.Certificate), util.SizeofEFIGUID)
	}
	cert.CertType = util.EFIGUID{
		Data1: binary.LittleEndian.Uint32(hdr.Certificate[0:4]),
		Data2: binary.LittleEndian.Uint16(hdr.Certificate[4:6]),
		Data3: binary.LittleEndian.Uint16(hdr.Certificate[6:8]),
	}
	copy(cert.CertType.Data4[:], hdr.Certificate[8:util.SizeofEFIGUID])
	// Defensive copy so callers cannot alias and mutate the table buffer.
	cert.CertData = append([]byte(nil), hdr.Certificate[util.SizeofEFIGUID:]...)
	return cert, nil
}

func WriteWinCertificateUEFIGUID(b *bytes.Buffer, w *WinCertificateUEFIGUID) {
	WriteWinCertificate(b, &w.Header)
	if err := binary.Write(b, binary.LittleEndian, w.CertType); err != nil {
		log.Fatal(err)
	}
	if err := binary.Write(b, binary.LittleEndian, w.CertData); err != nil {
		log.Fatal(err)
	}
}

// Page. 238
// Only used when EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS is set
type EFIVariableAuthentication3 struct {
	Version      uint8
	Type         uint8
	MetadataSize uint32
	Flags        uint32
}

// Page. 238
// Only accepts the CertType EFI_CERT_TYPE_PKCS7_GUID
type EFIVariableAuthentication2 struct {
	Time     util.EFITime
	AuthInfo WinCertificateUEFIGUID
}

// Returns an EFIVariableAuthencation2 struct
// no SignedData
func NewEFIVariableAuthentication2() *EFIVariableAuthentication2 {
	return &EFIVariableAuthentication2{
		Time: *util.NewEFITime(),
		AuthInfo: WinCertificateUEFIGUID{
			Header: WINCertificate{
				Length:   SizeofWinCertificateUEFIGUID,
				Revision: WIN_CERTIFICATE_REVISION,
				CertType: WIN_CERT_TYPE_EFI_GUID,
			},
			CertType: EFI_CERT_TYPE_PKCS7_GUID,
		},
	}
}

func (e *EFIVariableAuthentication2) Marshal(b *bytes.Buffer) {
	WriteEFIVariableAuthencation2(b, *e)
}

func (e *EFIVariableAuthentication2) Unmarshal(b *bytes.Buffer) error {
	auth, err := ReadEFIVariableAuthencation2(b)
	if err != nil {
		return err
	}
	*e = *auth
	return nil
}

func (e *EFIVariableAuthentication2) Verify(cert *x509.Certificate) (bool, error) {
	signature, err := pkcs7.ParsePKCS7(e.AuthInfo.CertData)
	if err != nil {
		return false, err
	}
	return signature.Verify(cert)
}

// We should maybe not duplicate this
// TODO: Remove this
// See efivarfs/types.go
type efibytes bytes.Buffer

func (e efibytes) Marshal(b *bytes.Buffer) {
	if _, err := io.Copy(b, (*bytes.Buffer)(&e)); err != nil {
		return
	}
}

func (e efibytes) Bytes() []byte {
	var b bytes.Buffer
	e.Marshal(&b)
	return b.Bytes()
}

func SignEFIVariable(v efivar.Efivar, m efivar.Marshallable, key crypto.Signer, cert *x509.Certificate) (*EFIVariableAuthentication2, efivar.Marshallable, error) {
	authvar := NewEFIVariableAuthentication2()

	// Bytes of the signaturedatabase (probably)
	var sb bytes.Buffer

	// Buffer for the bytes we are signing
	var buf bytes.Buffer

	s := []byte{}
	for _, n := range []byte(v.Name) {
		s = append(s, n, 0x00)
	}

	// Marshal the bytes so we can include them in for our signed data
	m.Marshal(&sb)

	writeOrder := []interface{}{
		s,
		*v.GUID,
		v.Attributes,
		authvar.Time,
		sb.Bytes(),
	}
	for _, d := range writeOrder {
		if err := binary.Write(&buf, binary.LittleEndian, d); err != nil {
			log.Fatal(err)
		}
	}

	der, err := pkcs7.SignPKCS7(key, cert, pkcs7.OIDData, buf.Bytes())
	if err != nil {
		return nil, nil, err
	}

	// We need to unwrap the outer ContentInfo layer
	cs := cryptobyte.String(der)
	_, signature, err := pkcs7.ParseContentInfo(&cs)
	if err != nil {
		return nil, nil, err
	}

	authvar.AuthInfo.Header.Length += uint32(len(signature))
	authvar.AuthInfo.CertData = signature

	// Create a marshallable variable we can give to WriteVar
	// Wrapper which contains the Auth header with the Marshallable bytes behind
	var auth efibytes
	authvar.Marshal((*bytes.Buffer)(&auth))
	m.Marshal((*bytes.Buffer)(&auth))

	return authvar, auth, nil
}

func ReadEFIVariableAuthencation2(f io.Reader) (*EFIVariableAuthentication2, error) {
	var efi EFIVariableAuthentication2
	if err := binary.Read(f, binary.LittleEndian, &efi.Time); err != nil {
		return nil, errors.Wrap(err, "could not parse EFI time")
	}
	authinfo, err := ReadWinCertificateUEFIGUID(f)
	if err != nil {
		return &EFIVariableAuthentication2{}, errors.Wrap(err, "could not parse WINCertificate UEFI_GUID")
	}
	efi.AuthInfo = authinfo
	if efi.AuthInfo.Header.CertType != WIN_CERT_TYPE_EFI_GUID {
		return nil, errors.Wrapf(ErrCertificateType, "EFI_VARIABLE_AUTHENTICATION2 accepts only CertType WIN_CERT_TYPE_EFI_GUID. Got: %x", efi.AuthInfo.Header.CertType)
	}
	if !util.CmpEFIGUID(efi.AuthInfo.CertType, EFI_CERT_TYPE_PKCS7_GUID) {
		return nil, errors.Wrapf(ErrCertificateType, "EFI_VARIABLE_AUTHENTICATION2 accepts only the EFI_CERT_TYPE_PKCS7_GUID certificate type. Got: %s", efi.AuthInfo.CertType.Format())
	}
	return &efi, nil
}

func WriteEFIVariableAuthencation2(b *bytes.Buffer, e EFIVariableAuthentication2) {
	if err := binary.Write(b, binary.LittleEndian, e.Time); err != nil {
		log.Fatal(err)
	}
	WriteWinCertificateUEFIGUID(b, &e.AuthInfo)
}

// Page. 237
// Deprecated. But defined because #reasons
type EFIVariableAuthentication struct {
	MonotonicCount uint64
	AuthInfo       util.EFIGUID // WIN_CERTIFICATE_UEFI_GUID
}
