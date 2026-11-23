package signature

import (
	"sort"
	"sync"

	"github.com/pkg/errors"

	"github.com/foxboron/go-uefi/efi/util"
)

// SignatureScheme describes the security rules the UEFI specification
// (section 32.4.1, "Signature Database") defines for one signature type.
//
// The rules are used both when reading an encoded EFI_SIGNATURE_LIST and when
// editing a SignatureList or SignatureDatabase, which is what keeps the two
// directions consistent. The rules are looked up for every operation, so
// registering or replacing a scheme takes effect for all subsequent
// operations.
type SignatureScheme struct {
	// GUID is the SignatureType this scheme describes.
	GUID util.EFIGUID
	// Type is the human readable name of the signature type.
	Type CertType
	// Size is the total size of one EFI_SIGNATURE_DATA entry, including the
	// SignatureOwner GUID. A zero Size means the entry size is variable
	// (currently only X509 certificates), in which case MinSize is the
	// smallest allowed entry.
	Size uint32
	// MinSize is the smallest allowed entry size when Size is zero.
	MinSize uint32
	// HeaderSize is the only SignatureHeaderSize the signature type allows.
	// All types defined by the specification require a zero sized header.
	HeaderSize uint32
	// AllowPEM signals that data appended to the signature database may be a
	// PEM encoded certificate; it is normalized to DER before it is stored so
	// that reads, writes and removes operate on the same bytes.
	AllowPEM bool
}

// ErrInvalidSignatureScheme is returned when a scheme is registered with
// security rules that can never describe a valid signature list.
var ErrInvalidSignatureScheme = errors.New("invalid signature scheme")

// MaxSignatureListSize is the largest EFI_SIGNATURE_LIST ReadSignatureList is
// willing to parse. The specification does not define an upper bound, but a
// signature database is read from untrusted storage (and from the firmware)
// and a bogus SignatureListSize must not turn into a multi-gigabyte
// allocation. The limit can be changed by callers that need to handle larger
// databases; it is consulted for every read.
var MaxSignatureListSize uint32 = 64 << 20

var (
	schemesMu sync.RWMutex
	// signatureSchemes holds the explicit rules for the signature types the
	// library knows about.
	signatureSchemes = defaultSignatureSchemes()
)

const sizeOfSignatureData = util.SizeofEFIGUID

// defaultSignatureSchemes returns the rules for every signature type defined
// by the UEFI specification, with the entry sizes documented in
// MdePkg/Include/Guid/ImageAuthentication.h.
func defaultSignatureSchemes() map[util.EFIGUID]SignatureScheme {
	return map[util.EFIGUID]SignatureScheme{
		CERT_SHA256_GUID:              {GUID: CERT_SHA256_GUID, Type: CERT_SHA256, Size: sizeOfSignatureData + 32},
		CERT_SHA1_GUID:                {GUID: CERT_SHA1_GUID, Type: CERT_SHA1, Size: sizeOfSignatureData + 20},
		CERT_SHA224_GUID:              {GUID: CERT_SHA224_GUID, Type: CERT_SHA224, Size: sizeOfSignatureData + 28},
		CERT_SHA384_GUID:              {GUID: CERT_SHA384_GUID, Type: CERT_SHA384, Size: sizeOfSignatureData + 48},
		CERT_SHA512_GUID:              {GUID: CERT_SHA512_GUID, Type: CERT_SHA512, Size: sizeOfSignatureData + 64},
		CERT_SM3_GUID:                 {GUID: CERT_SM3_GUID, Type: CERT_SM3, Size: sizeOfSignatureData + 32},
		CERT_RSA2048_GUID:             {GUID: CERT_RSA2048_GUID, Type: CERT_RSA2048, Size: sizeOfSignatureData + 256},
		CERT_RSA2048_SHA256_GUID:      {GUID: CERT_RSA2048_SHA256_GUID, Type: CERT_RSA2048_SHA256, Size: sizeOfSignatureData + 256},
		CERT_RSA2048_SHA1_GUID:        {GUID: CERT_RSA2048_SHA1_GUID, Type: CERT_RSA2048_SHA1, Size: sizeOfSignatureData + 256},
		CERT_X509_GUID:                {GUID: CERT_X509_GUID, Type: CERT_X509, MinSize: sizeOfSignatureData + 1, AllowPEM: true},
		CERT_X509_SHA256_GUID:         {GUID: CERT_X509_SHA256_GUID, Type: CERT_X509_SHA256, Size: sizeOfSignatureData + 48},
		CERT_X509_SHA384_GUID:         {GUID: CERT_X509_SHA384_GUID, Type: CERT_X509_SHA384, Size: sizeOfSignatureData + 64},
		CERT_X509_SHA512_GUID:         {GUID: CERT_X509_SHA512_GUID, Type: CERT_X509_SHA512, Size: sizeOfSignatureData + 80},
		CERT_X509_SM3_GUID:            {GUID: CERT_X509_SM3_GUID, Type: CERT_X509_SM3, Size: sizeOfSignatureData + 48},
		CERT_EXTERNAL_MANAGEMENT_GUID: {GUID: CERT_EXTERNAL_MANAGEMENT_GUID, Type: CERT_EXTERNAL_MANAGEMENT, Size: sizeOfSignatureData + 1},
	}
}

// LookupSignatureScheme returns the rules for a signature type.
//
// A GUID that is only present in ValidEFISignatureSchemes keeps working with
// the historical behaviour: it is treated as a variable length signature type.
// A GUID that is not known at all is reported as unknown.
func LookupSignatureScheme(certtype util.EFIGUID) (SignatureScheme, bool) {
	schemesMu.RLock()
	defer schemesMu.RUnlock()
	if scheme, ok := signatureSchemes[certtype]; ok {
		return scheme, true
	}
	if name, ok := ValidEFISignatureSchemes[certtype]; ok {
		return SignatureScheme{
			GUID:    certtype,
			Type:    name,
			MinSize: sizeOfSignatureData + 1,
		}, true
	}
	return SignatureScheme{}, false
}

// RegisteredSignatureSchemes returns a stable (GUID sorted) snapshot of the
// signature rules currently in effect.
func RegisteredSignatureSchemes() []SignatureScheme {
	schemesMu.RLock()
	defer schemesMu.RUnlock()
	schemes := make([]SignatureScheme, 0, len(signatureSchemes))
	for _, scheme := range signatureSchemes {
		schemes = append(schemes, scheme)
	}
	sort.Slice(schemes, func(i, j int) bool {
		a, b := schemes[i].GUID, schemes[j].GUID
		if a.Data1 != b.Data1 {
			return a.Data1 < b.Data1
		}
		if a.Data2 != b.Data2 {
			return a.Data2 < b.Data2
		}
		if a.Data3 != b.Data3 {
			return a.Data3 < b.Data3
		}
		for k := 0; k < len(a.Data4); k++ {
			if a.Data4[k] != b.Data4[k] {
				return a.Data4[k] < b.Data4[k]
			}
		}
		return false
	})
	return schemes
}

// RegisterSignatureScheme installs (or replaces) the security rules for a
// signature type. The registration is used by every subsequent read, write,
// append, remove and validation; there is no cached state. The type is also
// made visible through ValidEFISignatureSchemes so existing consumers keep
// working.
func RegisterSignatureScheme(scheme SignatureScheme) error {
	if scheme.Size == 0 && scheme.MinSize < sizeOfSignatureData+1 {
		return errors.Wrapf(ErrInvalidSignatureScheme,
			"variable length signatures must be at least %d bytes, got %d",
			sizeOfSignatureData+1, scheme.MinSize)
	}
	if scheme.Size != 0 && scheme.Size < sizeOfSignatureData+1 {
		return errors.Wrapf(ErrInvalidSignatureScheme,
			"signature entries must be at least %d bytes, got %d",
			sizeOfSignatureData+1, scheme.Size)
	}
	schemesMu.Lock()
	defer schemesMu.Unlock()
	if scheme.Type == "" {
		name, ok := ValidEFISignatureSchemes[scheme.GUID]
		if !ok {
			return errors.Wrapf(ErrInvalidSignatureScheme,
				"missing name for unknown signature type %s", scheme.GUID.Format())
		}
		scheme.Type = name
	}
	signatureSchemes[scheme.GUID] = scheme
	ValidEFISignatureSchemes[scheme.GUID] = scheme.Type
	return nil
}

// UnregisterSignatureScheme removes the explicit security rules for a
// signature type. Subsequent operations fall back to the rules (if any) the
// GUID has in ValidEFISignatureSchemes.
func UnregisterSignatureScheme(certtype util.EFIGUID) {
	schemesMu.Lock()
	defer schemesMu.Unlock()
	delete(signatureSchemes, certtype)
	delete(ValidEFISignatureSchemes, certtype)
}

// ResetSignatureSchemes restores the default security rules, discarding all
// registrations made with RegisterSignatureScheme.
func ResetSignatureSchemes() {
	schemesMu.Lock()
	defer schemesMu.Unlock()
	for guid := range signatureSchemes {
		delete(ValidEFISignatureSchemes, guid)
	}
	signatureSchemes = defaultSignatureSchemes()
	for guid, scheme := range signatureSchemes {
		ValidEFISignatureSchemes[guid] = scheme.Type
	}
}
