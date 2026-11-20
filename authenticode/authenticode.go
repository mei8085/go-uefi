// Package authenticode implements the Microsoft Authenticode standard.
//
// It allows parsing, verifying and signing of PE/COFF binaries.
package authenticode

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	encasn1 "encoding/asn1"
	"errors"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"

	"github.com/foxboron/go-uefi/pkcs7"
)

var (
	OIDSpcIndirectDataContent         = encasn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}
	OIDSpcPEImageDataObjID            = encasn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 15}
	OIDMicrosoftIndividualCodeSigning = encasn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 21}
)

// Errors returned by Authenticode parsing and verification. They are exported
// so callers can distinguish a structurally invalid signature (which must be
// rejected outright) from a signature that simply fails to validate.
var (
	// ErrMalformedSpcIndirectData is returned when the SPC_INDIRECT_DATA
	// content cannot be strictly parsed or contains bytes outside its
	// declared ASN.1 boundaries.
	ErrMalformedSpcIndirectData = errors.New("malformed SPC_INDIRECT_DATA content")

	// ErrDigestMismatch is returned when the digest computed over the image
	// does not equal the digest embedded in the (signed) SPC_INDIRECT_DATA.
	ErrDigestMismatch = errors.New("image digest does not match the authenticated digest")
)

// Authenticode represents an authenticode signature.
type Authenticode struct {
	Pkcs   *pkcs7.PKCS7
	Algid  *pkix.AlgorithmIdentifier
	Digest []byte
}

// Verify validates an authenticode signature.
// Note it doesn't validate x509 certificate chains.
//
// The image is hashed and compared against the digest embedded in the signed
// SPC_INDIRECT_DATA. A mismatch returns ErrDigestMismatch so callers can tell
// a tampered (or appended-to) image apart from an untrusted certificate.
func (a *Authenticode) Verify(cert *x509.Certificate, img io.Reader, opts ...pkcs7.VerifyOption) (bool, error) {
	var h hash.Hash
	switch {
	case a.Algid.Algorithm.Equal(pkcs7.OIDDigestAlgorithmSHA256):
		h = crypto.SHA256.New()
	default:
		return false, errors.New("unsupported hashing function")
	}

	if h.Size() != len(a.Digest) {
		return false, errors.New("wrong block size")
	}

	if _, err := io.Copy(h, img); err != nil {
		return false, err
	}

	digest := h.Sum(nil)
	if !bytes.Equal(digest, a.Digest) {
		return false, fmt.Errorf("%w: expected %x, got %x", ErrDigestMismatch, a.Digest, digest)
	}
	return a.Pkcs.Verify(cert, opts...)
}

// CreateSpcIndirectDataContent creates the SPCIndirectDataContent container as
// specified int he Authenticode standard.
func CreateSpcIndirectDataContent(digest []byte, alg crypto.Hash) ([]byte, error) {
	var b cryptobyte.Builder

	//		data           SpcAttributeTypeAndOptionalValue,
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {

		//		type   ObjectID,
		b.AddASN1ObjectIdentifier(OIDSpcPEImageDataObjID)

		//	SpcPeImageData ::= SEQUENCE {
		b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {

			//		flags                   SpcPeImageFlags DEFAULT { includeResources },
			//	SpcPeImageFlags ::= BIT STRING {
			//		includeResources            (0),
			//		includeDebugInfo            (1),
			//		includeImportAddressTable   (2)
			//	}
			// We could also pass '0' but my reference implementation has one NULL byte, and not two NULL bytes.
			b.AddASN1BitString(nil)

			//		file                    SpcLink
			// SpcLink ::= CHOICE {
			//		url                     [0] IMPLICIT IA5STRING,
			//		moniker                 [1] IMPLICIT SpcSerializedObject,
			//		file                    [2] EXPLICIT SpcString
			//	} --#public--
			b.AddASN1(asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {

				//		file                    [2] EXPLICIT SpcString
				b.AddASN1(asn1.Tag(2).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {

					//		unicode                 [0] IMPLICIT BMPSTRING,
					b.AddASN1(asn1.Tag(0).ContextSpecific(), func(b *cryptobyte.Builder) {

						// <<<Obsolete>>>, but with null bytes after each bytes. idk why.
						s := []byte{0x00, 0x3c, 0x00, 0x3c, 0x00, 0x3c, 0x00, 0x4f, 0x00, 0x62,
							0x00, 0x73, 0x00, 0x6f, 0x00, 0x6c, 0x00, 0x65, 0x00, 0x74,
							0x00, 0x65, 0x00, 0x3e, 0x00, 0x3e, 0x00, 0x3E}
						b.AddBytes(s)

					})
				})
			})
		})
	})

	//	DigestInfo ::= SEQUENCE {
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {

		//		digestAlgorithm  AlgorithmIdentifier,
		b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {

			//		digestAlgorithm  AlgorithmIdentifier,
			b.AddASN1ObjectIdentifier(pkcs7.OIDDigestAlgorithmSHA256)

			// Add explicit null, I believe it's needed by picky UEFI things
			b.AddASN1NULL()
		})

		//		digest           OCTETSTRING
		b.AddASN1OctetString(digest)
	})

	return b.Bytes()
}

// SignAuthenticode signs a digest with the SPC Indirect Data Content as
// specified by the authenticode standard.
func SignAuthenticode(signer crypto.Signer, cert *x509.Certificate, digest io.Reader, alg crypto.Hash, opts ...pkcs7.Option) ([]byte, error) {
	h := alg.New()

	if _, err := io.Copy(h, digest); err != nil {
		return nil, err
	}

	b, err := CreateSpcIndirectDataContent(h.Sum(nil), alg)
	if err != nil {
		return nil, fmt.Errorf("failed creating SpcIndirectDataContent: %w", err)
	}
	return pkcs7.SignPKCS7(signer, cert, OIDSpcIndirectDataContent, b, opts...)
}

// ParseAuthenticode parses an Authenticode signature.
//
// Every ASN.1 level is parsed to completion. The signed SPC_INDIRECT_DATA
// content is the boundary that the signature digest covers: any byte left over
// inside or between its elements is data the signature does not authenticate,
// so it is rejected rather than silently skipped. Structural failures are
// wrapped around ErrMalformedSpcIndirectData (or the underlying pkcs7 errors)
// so callers can identify them through errors.Is.
func ParseAuthenticode(b []byte) (*Authenticode, error) {
	var auth Authenticode
	pkcs, err := pkcs7.ParsePKCS7(b)
	if err != nil {
		return nil, fmt.Errorf("failed parsing authenticode: %w", err)
	}

	if !pkcs.OID.Equal(OIDSpcIndirectDataContent) {
		return nil, fmt.Errorf("not an authenticode siganture")
	}

	auth.Pkcs = pkcs

	// The explicit content must hold exactly one SPC_INDIRECT_DATA SEQUENCE.
	der := cryptobyte.String(pkcs.ContentInfo)
	var indirectData cryptobyte.String
	if !der.ReadASN1(&indirectData, asn1.SEQUENCE) {
		return nil, fmt.Errorf("%w: no SPC_INDIRECT_DATA SEQUENCE", ErrMalformedSpcIndirectData)
	}
	if !der.Empty() {
		return nil, fmt.Errorf("%w: %d unconsumed byte(s) after SPC_INDIRECT_DATA", ErrMalformedSpcIndirectData, len(der))
	}

	// First element: SpcAttributeTypeAndOptionalValue.
	var spcdata cryptobyte.String
	if !indirectData.ReadASN1(&spcdata, asn1.SEQUENCE) {
		return nil, fmt.Errorf("%w: missing SpcAttributeTypeAndOptionalValue", ErrMalformedSpcIndirectData)
	}

	var dtype encasn1.ObjectIdentifier
	if !spcdata.ReadASN1ObjectIdentifier(&dtype) {
		return nil, fmt.Errorf("%w: missing objectid type", ErrMalformedSpcIndirectData)
	}

	// TODO: Apparently microsoft sometimes uses a special OID for shim keys
	if !dtype.Equal(OIDSpcPEImageDataObjID) && !dtype.Equal(OIDMicrosoftIndividualCodeSigning) {
		return nil, fmt.Errorf("%w: incorrect data type, expected %v, got %v", ErrMalformedSpcIndirectData, OIDSpcIndirectDataContent, dtype)
	}

	// The SpcPeImageData (flags + SpcLink). Skip the value but enforce that
	// nothing trails it inside SpcAttributeTypeAndOptionalValue.
	var spcPeImageData cryptobyte.String
	if !spcdata.ReadASN1(&spcPeImageData, asn1.SEQUENCE) {
		return nil, fmt.Errorf("%w: no SpcPeImageData", ErrMalformedSpcIndirectData)
	}
	if !spcdata.Empty() {
		return nil, fmt.Errorf("%w: %d unconsumed byte(s) in SpcAttributeTypeAndOptionalValue", ErrMalformedSpcIndirectData, len(spcdata))
	}

	// Second element: DigestInfo (AlgorithmIdentifier + digest OCTET STRING).
	var digestInfo cryptobyte.String
	if !indirectData.ReadASN1(&digestInfo, asn1.SEQUENCE) {
		return nil, fmt.Errorf("%w: missing DigestInfo", ErrMalformedSpcIndirectData)
	}
	if !indirectData.Empty() {
		return nil, fmt.Errorf("%w: %d unconsumed byte(s) in SPC_INDIRECT_DATA", ErrMalformedSpcIndirectData, len(indirectData))
	}

	algid, err := pkcs7.ParseAlgorithmIdentifier(&digestInfo)
	if err != nil {
		return nil, fmt.Errorf("%w: failed parsing DigestInfo: %v", ErrMalformedSpcIndirectData, err)
	}
	auth.Algid = algid

	var digest cryptobyte.String
	if !digestInfo.ReadASN1(&digest, asn1.OCTET_STRING) {
		return nil, fmt.Errorf("%w: missing digest OCTET STRING", ErrMalformedSpcIndirectData)
	}
	if !digestInfo.Empty() {
		return nil, fmt.Errorf("%w: %d unconsumed byte(s) in DigestInfo", ErrMalformedSpcIndirectData, len(digestInfo))
	}

	auth.Digest = digest

	return &auth, nil
}
