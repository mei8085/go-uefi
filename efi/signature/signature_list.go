package signature

import (
	"bytes"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math"
	"reflect"

	"github.com/foxboron/go-uefi/efi/util"
	"github.com/pkg/errors"
)

// Section 32.4.1 Signature Database
// Page 1714 -> Page 1717
var (
	CERT_SHA256_GUID         = util.EFIGUID{0xc1c41626, 0x504c, 0x4092, [8]uint8{0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28}}
	CERT_RSA2048_GUID        = util.EFIGUID{0x3c5766e8, 0x269c, 0x4e34, [8]uint8{0xaa, 0x14, 0xed, 0x77, 0x6e, 0x85, 0xb3, 0xb6}}
	CERT_RSA2048_SHA256_GUID = util.EFIGUID{0xe2b36190, 0x879b, 0x4a3d, [8]uint8{0xad, 0x8d, 0xf2, 0xe7, 0xbb, 0xa3, 0x27, 0x84}}

	CERT_SHA1_GUID         = util.EFIGUID{0x826ca512, 0xcf10, 0x4ac9, [8]uint8{0xb1, 0x87, 0xbe, 0x01, 0x49, 0x66, 0x31, 0xbd}}
	CERT_RSA2048_SHA1_GUID = util.EFIGUID{0x67f8444f, 0x8743, 0x48f1, [8]uint8{0xa3, 0x28, 0x1e, 0xaa, 0xb8, 0x73, 0x60, 0x80}}

	CERT_X509_GUID = util.EFIGUID{0xa5c059a1, 0x94e4, 0x4aa7, [8]uint8{0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72}}

	CERT_SHA224_GUID = util.EFIGUID{0xb6e5233, 0xa65c, 0x44c9, [8]uint8{0x94, 0x07, 0xd9, 0xab, 0x83, 0xbf, 0xc8, 0xbd}}

	CERT_SHA384_GUID = util.EFIGUID{0xff3e5307, 0x9fd0, 0x48c9, [8]uint8{0x85, 0xf1, 0x8a, 0xd5, 0x6c, 0x70, 0x1e, 0x01}}

	CERT_SHA512_GUID = util.EFIGUID{0x93e0fae, 0xa6c4, 0x4f50, [8]uint8{0x9f, 0x1b, 0xd4, 0x1e, 0x2b, 0x89, 0xc1, 0x9a}}

	CERT_SM3_GUID = util.EFIGUID{0x57347f87, 0x7a9b, 0x403a, [8]uint8{0xb9, 0x3c, 0xdc, 0x4a, 0xfb, 0x7a, 0x0e, 0xbc}}

	CERT_X509_SHA256_GUID = util.EFIGUID{0x3bd2a492, 0x96c0, 0x4079, [8]uint8{0xb4, 0x20, 0xfc, 0xf9, 0x8e, 0xf1, 0x03, 0xed}}

	CERT_X509_SHA384_GUID = util.EFIGUID{0x7076876e, 0x80c2, 0x4ee6, [8]uint8{0xaa, 0xd2, 0x28, 0xb3, 0x49, 0xa6, 0x86, 0x5b}}

	CERT_X509_SHA512_GUID = util.EFIGUID{0x446dbf63, 0x2502, 0x4cda, [8]uint8{0xbc, 0xfa, 0x24, 0x65, 0xd2, 0xb0, 0xfe, 0x9d}}

	CERT_X509_SM3_GUID = util.EFIGUID{0x60d807e5, 0x10b4, 0x49a9, [8]uint8{0x93, 0x31, 0xe4, 0x04, 0x37, 0x88, 0x8d, 0x37}}

	CERT_EXTERNAL_MANAGEMENT_GUID = util.EFIGUID{0x452e8ced, 0xdfff, 0x4b8c, [8]uint8{0xae, 0x01, 0x51, 0x18, 0x86, 0x2e, 0x68, 0x2c}}
)

type CertType string

var ErrNoSuchSignatureScheme = errors.New("no such signature scheme")

// Quick access list
// Maybe a map[string]EFIGUID?
//
// The map is part of the public API and is consulted by LookupSignatureScheme
// for GUIDs without explicit SignatureScheme rules. Rules registered with
// RegisterSignatureScheme are reflected here as well.
var ValidEFISignatureSchemes = map[util.EFIGUID]CertType{
	CERT_SHA256_GUID:              "SHA256",
	CERT_RSA2048_GUID:             "RSA2048",
	CERT_RSA2048_SHA256_GUID:      "RSA2048 SHA256",
	CERT_SHA1_GUID:                "SHA1",
	CERT_RSA2048_SHA1_GUID:        "RSA2048 SHA1",
	CERT_X509_GUID:                "X509",
	CERT_SHA224_GUID:              "SHA224",
	CERT_SHA384_GUID:              "SHA238",
	CERT_SHA512_GUID:              "SHA512",
	CERT_SM3_GUID:                 "SM3",
	CERT_X509_SHA256_GUID:         "X509 SHA256",
	CERT_X509_SHA384_GUID:         "X509 SHA384",
	CERT_X509_SHA512_GUID:         "X509 SHA512",
	CERT_X509_SM3_GUID:            "X509 SM3",
	CERT_EXTERNAL_MANAGEMENT_GUID: "EXTERNAL MANAGEMENT",
}

const (
	CERT_SHA256              CertType = "SHA256"
	CERT_RSA2048                      = "RSA2048"
	CERT_RSA2048_SHA256               = "RSA2048 SHA256"
	CERT_SHA1                         = "SHA1"
	CERT_RSA2048_SHA1                 = "RSA2048 SHA1"
	CERT_X509                         = "X509"
	CERT_SHA224                       = "SHA224"
	CERT_SHA384                       = "SHA238"
	CERT_SHA512                       = "SHA512"
	CERT_SM3                          = "SM3"
	CERT_X509_SHA256                  = "X509 SHA256"
	CERT_X509_SHA384                  = "X509 SHA384"
	CERT_X509_SHA512                  = "X509 SHA512"
	CERT_X509_SM3                     = "X509 SM3"
	CERT_EXTERNAL_MANAGEMENT          = "EXTERNAL MANAGEMENT"
)

// Section 3.3 - Globally Defined Variables
// Array of GUIDs representing the type of signatures supported by
// the platform firmware. Should be treated as read-only
func GetSupportedSignatures(f io.Reader) ([]util.EFIGUID, error) {
	// This is a bit bad. But io.Reader is *probably nicer* but we need to know
	// the length in a better way.
	buf := new(bytes.Buffer)
	buf.ReadFrom(f)
	supportedSigs := make([]util.EFIGUID, buf.Len()/16)
	if err := binary.Read(buf, binary.LittleEndian, &supportedSigs); err != nil {
		return nil, errors.Wrapf(err, "could not parse EFIGUIDs from this reader")
	}
	return supportedSigs, nil
}

// Section 32.4.1 - Signature Database
// Page 1712
type SignatureData struct {
	Owner util.EFIGUID
	Data  []uint8
}

// Size returns the encoded size of the signature data, EFI_SIGNATURE_DATA
// being a SignatureOwner GUID followed by the signature bytes.
func (sd *SignatureData) Size() uint32 {
	return util.SizeofEFIGUID + uint32(len(sd.Data))
}

func ReadSignatureData(f io.Reader, size uint32) (*SignatureData, error) {
	if size < util.SizeofEFIGUID {
		return &SignatureData{}, errors.Wrapf(ErrInvalidSignatureList,
			"signature size %d is smaller than the signature owner GUID (%d bytes)",
			size, util.SizeofEFIGUID)
	}
	s := SignatureData{}
	if err := binary.Read(f, binary.LittleEndian, &s.Owner); err != nil {
		return &SignatureData{}, errors.Wrapf(err, "could not read Signature Data")
	}
	data := make([]uint8, size-util.SizeofEFIGUID) // Subtract the size of Owner
	if err := binary.Read(f, binary.LittleEndian, &data); err != nil {
		return &SignatureData{}, errors.Wrapf(err, "Couldn't read Signature Data")
	}
	s.Data = data[:]
	return &s, nil
}

func WriteSignatureData(b io.Writer, s SignatureData) {
	for _, v := range []interface{}{s.Owner, s.Data} {
		err := binary.Write(b, binary.LittleEndian, v)
		if err != nil {
			log.Fatalf("Couldn't write signature data: %s", err)
		}
	}
}

func (sd *SignatureData) Bytes() []byte {
	buf := new(bytes.Buffer)
	WriteSignatureData(buf, *sd)
	return buf.Bytes()
}

// Section 32.4.1 - Signature Database
// Page 1713
type SignatureList struct {
	SignatureType   util.EFIGUID
	ListSize        uint32          // Total size of the signature list, including this header
	HeaderSize      uint32          // Size of SignatureHead
	Size            uint32          // Size of each signature. At least the size of EFI_SIGNATURE_DATA
	SignatureHeader []uint8         // SignatureType defines the content of this header
	Signatures      []SignatureData // SignatureData List
}

// SignatureSize + sizeof(SignatureType) + sizeof(uint32)*3
const SizeofSignatureList uint32 = util.SizeofEFIGUID + 4 + 4 + 4

var (
	ErrNotFoundSigData      = errors.New("signature data not found")
	ErrSigDataExists        = errors.New("signature data exists already")
	ErrInvalidSignatureList = errors.New("invalid signature list")
	// ErrSigSizeMismatch is returned when the size of a signature entry does
	// not match the size the signature type mandates.
	ErrSigSizeMismatch = errors.New("signature data size does not match the signature type")
)

func NewSignatureList(certtype util.EFIGUID) *SignatureList {
	return &SignatureList{
		SignatureType:   certtype,
		ListSize:        SizeofSignatureList,
		HeaderSize:      0,
		Size:            0,
		SignatureHeader: []uint8{},
		Signatures:      []SignatureData{},
	}
}

// normalizeSignatureData converts PEM encoded certificates to DER when the
// signature type allows it. This is applied on append, lookup and remove, so
// the same value is found no matter which encoding the caller uses.
func normalizeSignatureData(scheme SignatureScheme, data []byte) []byte {
	if scheme.AllowPEM {
		if block, _ := pem.Decode(data); block != nil {
			return block.Bytes
		}
	}
	return data
}

// validateSignatureData verifies a signature payload against the size rules of
// its signature type. The payload is expected to be normalized already.
func validateSignatureData(scheme SignatureScheme, data []byte) (uint32, error) {
	entrySize := util.SizeofEFIGUID + uint32(len(data))
	if err := checkEntrySize(scheme, entrySize); err != nil {
		return 0, err
	}
	return entrySize, nil
}

// checkEntrySize verifies an encoded EFI_SIGNATURE_DATA size against the rules
// of a signature type. It is shared by the reader and the editor so both
// directions agree on the length boundary.
func checkEntrySize(scheme SignatureScheme, entrySize uint32) error {
	if scheme.Size != 0 {
		if entrySize != scheme.Size {
			return errors.Wrapf(ErrSigSizeMismatch,
				"signature type %s mandates %d byte entries, got %d",
				scheme.Type, scheme.Size, entrySize)
		}
		return nil
	}
	if entrySize < scheme.MinSize {
		return errors.Wrapf(ErrSigSizeMismatch,
			"signature type %s mandates at least %d byte entries, got %d",
			scheme.Type, scheme.MinSize, entrySize)
	}
	return nil
}

// Compare the signature lists header to see if they are the same type of list
// This is usefull if you wonder if you can merge the lists or not
func (sl *SignatureList) CmpHeader(siglist *SignatureList) bool {
	if !util.CmpEFIGUID(sl.SignatureType, siglist.SignatureType) {
		return false
	}
	if sl.Size != siglist.Size {
		return false
	}
	if !reflect.DeepEqual(sl.SignatureHeader, siglist.SignatureHeader) {
		return false
	}
	return true
}

// Check if signature exists in the signature list
// Return true if it does along with the index
func (sl *SignatureList) Exists(sigdata *SignatureData) (bool, int) {
	data := sigdata.Data
	if scheme, ok := LookupSignatureScheme(sl.SignatureType); ok {
		data = normalizeSignatureData(scheme, data)
	}
	for index, sigs := range sl.Signatures {
		if !util.CmpEFIGUID(sigs.Owner, sigdata.Owner) {
			continue
		}
		if !bytes.Equal(sigs.Data, data) {
			continue
		}
		return true, index
	}
	return false, 0
}

func (sl *SignatureList) ExistsInList(siglist *SignatureList) bool {
	for _, item := range siglist.Signatures {
		if ok, _ := sl.Exists(&item); !ok {
			return false
		}
	}
	return true
}

func (sl *SignatureList) AppendBytes(owner util.EFIGUID, data []byte) error {
	scheme, ok := LookupSignatureScheme(sl.SignatureType)
	if !ok {
		return ErrNoSuchSignatureScheme
	}
	if sl.HeaderSize != scheme.HeaderSize {
		return errors.Wrapf(ErrInvalidSignatureList,
			"signature type %s mandates a %d byte signature header, list has %d",
			scheme.Type, scheme.HeaderSize, sl.HeaderSize)
	}
	// Normalize first: a PEM certificate must be compared, stored and sized as
	// the DER certificate it encodes.
	data = normalizeSignatureData(scheme, data)
	entrySize, err := validateSignatureData(scheme, data)
	if err != nil {
		return err
	}
	if ok, _ := sl.Exists(&SignatureData{owner, data}); ok {
		return ErrSigDataExists
	}
	// A signature list has a single signature size. Refuse to append data that
	// would break that invariant instead of silently rewriting the list size.
	if len(sl.Signatures) > 0 && sl.Size != entrySize {
		return errors.Wrapf(ErrSigSizeMismatch,
			"signature list holds %d byte entries, cannot append a %d byte entry",
			sl.Size, entrySize)
	}
	newListSize := uint64(sl.ListSize) + uint64(entrySize)
	if newListSize > uint64(math.MaxUint32) {
		return errors.Wrapf(ErrInvalidSignatureList,
			"signature list would grow to %d bytes, larger than the 32 bit list size",
			newListSize)
	}
	sl.Size = entrySize
	sl.Signatures = append(sl.Signatures, SignatureData{Owner: owner, Data: data})
	sl.ListSize = uint32(newListSize)
	return nil
}

func (sl *SignatureList) AppendSignature(s SignatureData) error {
	return sl.AppendBytes(s.Owner, s.Data)
}

func (sl *SignatureList) RemoveBytes(owner util.EFIGUID, data []byte) error {
	scheme, ok := LookupSignatureScheme(sl.SignatureType)
	if !ok {
		return ErrNoSuchSignatureScheme
	}
	data = normalizeSignatureData(scheme, data)
	ok, index := sl.Exists(&SignatureData{owner, data})
	if !ok {
		return ErrNotFoundSigData
	}
	if len(sl.Signatures) == 1 {
		*sl = *NewSignatureList(sl.SignatureType)
		return nil
	}
	sl.Signatures = append(sl.Signatures[:index], sl.Signatures[index+1:]...)
	sl.ListSize -= sl.Size
	return nil
}

func (sl *SignatureList) RemoveSignature(s SignatureData) error {
	return sl.RemoveBytes(s.Owner, s.Data)
}

// Validate checks that the signature list is internally consistent: the
// signature size, list size, header size and the size of every signature entry
// must match the rules of the signature type.
//
// AppendBytes and RemoveBytes maintain these invariants, so a list produced or
// edited through the API always validates. It is also usable to check lists
// built by hand before they are written to a variable.
func (sl *SignatureList) Validate() error {
	scheme, ok := LookupSignatureScheme(sl.SignatureType)
	if !ok {
		return errors.Wrapf(ErrNoSuchSignatureScheme, "%s", sl.SignatureType.Format())
	}
	if sl.HeaderSize != scheme.HeaderSize {
		return errors.Wrapf(ErrInvalidSignatureList,
			"signature type %s mandates a %d byte signature header, list has %d",
			scheme.Type, scheme.HeaderSize, sl.HeaderSize)
	}
	if uint32(len(sl.SignatureHeader)) != sl.HeaderSize {
		return errors.Wrapf(ErrInvalidSignatureList,
			"signature header holds %d bytes but HeaderSize is %d",
			len(sl.SignatureHeader), sl.HeaderSize)
	}
	if sl.ListSize < SizeofSignatureList {
		return errors.Wrapf(ErrInvalidSignatureList,
			"signature list size %d is smaller than the %d byte list header",
			sl.ListSize, SizeofSignatureList)
	}
	if len(sl.Signatures) == 0 {
		if sl.Size != 0 && scheme.Size != 0 && sl.Size != scheme.Size {
			return errors.Wrapf(ErrSigSizeMismatch,
				"signature type %s mandates %d byte entries, empty list has %d",
				scheme.Type, scheme.Size, sl.Size)
		}
		want := uint64(SizeofSignatureList) + uint64(sl.HeaderSize)
		if uint64(sl.ListSize) != want {
			return errors.Wrapf(ErrInvalidSignatureList,
				"empty signature list has list size %d, expected %d",
				sl.ListSize, want)
		}
		return nil
	}
	if sl.Size == 0 {
		return errors.Wrapf(ErrInvalidSignatureList,
			"signature list holds %d entries but has a zero signature size",
			len(sl.Signatures))
	}
	if err := checkEntrySize(scheme, sl.Size); err != nil {
		return err
	}
	for index, sig := range sl.Signatures {
		if sig.Size() != sl.Size {
			return errors.Wrapf(ErrSigSizeMismatch,
				"signature %d is %d bytes, signature list mandates %d", index, sig.Size(), sl.Size)
		}
	}
	want := uint64(SizeofSignatureList) + uint64(sl.HeaderSize) + uint64(len(sl.Signatures))*uint64(sl.Size)
	if uint64(sl.ListSize) != want {
		return errors.Wrapf(ErrInvalidSignatureList,
			"signature list has list size %d, expected %d for %d entries of %d bytes",
			sl.ListSize, want, len(sl.Signatures), sl.Size)
	}
	return nil
}

func (sl *SignatureList) Bytes() []byte {
	buf := new(bytes.Buffer)
	WriteSignatureList(buf, *sl)
	return buf.Bytes()
}

// Writes a signature list
func WriteSignatureList(b io.Writer, s SignatureList) {
	for _, v := range []interface{}{s.SignatureType, s.ListSize, s.HeaderSize, s.Size, s.SignatureHeader} {
		err := binary.Write(b, binary.LittleEndian, v)
		if err != nil {
			log.Fatalf("Couldn't write signature list: %s", err)
		}
	}
	for _, l := range s.Signatures {
		WriteSignatureData(b, l)
	}
}

// Read an EFI_SIGNATURE_LIST from io.Reader. It will read until io.EOF.
// io.EOF should be somewhat expected if we are trying to read multiple
// lists as they should be either at the end of the file, or the entire file.
//
// Every signature type known to LookupSignatureScheme can be read. The size
// rules of the signature type are enforced: a signature list whose
// SignatureSize does not match the type, or whose SignatureListSize is not
// exactly HeaderSize + SizeofSignatureList + n*SignatureSize, is rejected with
// ErrInvalidSignatureList instead of being silently accepted or truncated.
// A truncated list is reported as an error (never as a clean io.EOF).
func ReadSignatureList(f io.Reader) (*SignatureList, error) {
	s := SignatureList{}
	for _, i := range []interface{}{&s.SignatureType, &s.ListSize, &s.HeaderSize, &s.Size} {
		err := binary.Read(f, binary.LittleEndian, i)
		if errors.Is(err, io.EOF) {
			return &SignatureList{}, err
		} else if err != nil {
			return &SignatureList{}, errors.Wrapf(err, "couldn't read signature list")
		}
	}

	if s.ListSize < SizeofSignatureList {
		return &SignatureList{}, errors.Wrapf(ErrInvalidSignatureList,
			"signature list size %d is smaller than the %d byte list header",
			s.ListSize, SizeofSignatureList)
	}
	if s.ListSize > MaxSignatureListSize {
		return &SignatureList{}, errors.Wrapf(ErrInvalidSignatureList,
			"signature list size %d exceeds the configured maximum of %d bytes",
			s.ListSize, MaxSignatureListSize)
	}

	scheme, ok := LookupSignatureScheme(s.SignatureType)
	if !ok {
		return &SignatureList{}, fmt.Errorf("not implemented signature list certificate: %s", s.SignatureType.Format())
	}
	if s.HeaderSize != scheme.HeaderSize {
		return &SignatureList{}, errors.Wrapf(ErrInvalidSignatureList,
			"unexpected HeaderSize for %s. Should be %d, got %d",
			scheme.Type, scheme.HeaderSize, s.HeaderSize)
	}

	// The list size minus the size of the SignatureList struct is the space
	// left for the signature header and the signature array.
	totalSize := s.ListSize - SizeofSignatureList
	if s.HeaderSize > totalSize {
		return &SignatureList{}, errors.Wrapf(ErrInvalidSignatureList,
			"signature header size %d exceeds the %d bytes available in the list",
			s.HeaderSize, totalSize)
	}
	if s.HeaderSize > 0 {
		s.SignatureHeader = make([]uint8, s.HeaderSize)
		if _, err := io.ReadFull(f, s.SignatureHeader); err != nil {
			return &SignatureList{}, errors.Wrapf(ErrInvalidSignatureList,
				"truncated signature header: %v", err)
		}
		totalSize -= s.HeaderSize
	}

	if s.Size == 0 {
		if totalSize != 0 {
			return &SignatureList{}, errors.Wrapf(ErrInvalidSignatureList,
				"signature list holds %d bytes of signatures but has a zero signature size", totalSize)
		}
		return &s, nil
	}
	if err := checkEntrySize(scheme, s.Size); err != nil {
		return &SignatureList{}, err
	}
	if totalSize%s.Size != 0 {
		return &SignatureList{}, errors.Wrapf(ErrInvalidSignatureList,
			"signature list size %d is not a multiple of the %d byte signature size",
			s.ListSize, s.Size)
	}

	count := totalSize / s.Size
	// Do not size the slice from the untrusted header; an absurd count would
	// otherwise allocate on behalf of the attacker.
	capacity := count
	if capacity > 1024 {
		capacity = 1024
	}
	sigData := make([]SignatureData, 0, capacity)
	for i := uint32(0); i < count; i++ {
		sigdata, err := ReadSignatureData(f, s.Size)
		if err != nil {
			return &SignatureList{}, errors.Wrapf(ErrInvalidSignatureList,
				"truncated signature list: %v", err)
		}
		sigData = append(sigData, *sigdata)
	}
	s.Signatures = sigData
	return &s, nil
}
