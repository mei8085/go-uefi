package pkcs7

import (
	"bytes"
	encasn1 "encoding/asn1"
	"errors"
	"testing"

	"github.com/foxboron/go-uefi/internal/certtest"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// duplicateSignerInfo rebuilds a PKCS#7 blob whose SignerInfos SET contains
// two copies of the original SignerInfo. All other elements are copied as raw
// TLVs so the surrounding structure stays byte-identical.
func duplicateSignerInfo(t *testing.T, b []byte) []byte {
	t.Helper()

	ci := cryptobyte.String(b)
	var outerSeq cryptobyte.String
	if !ci.ReadASN1(&outerSeq, asn1.SEQUENCE) {
		t.Fatal("no outer ContentInfo")
	}
	var outerOID encasn1.ObjectIdentifier
	if !outerSeq.ReadASN1ObjectIdentifier(&outerOID) {
		t.Fatal("no outer oid")
	}
	var explicit cryptobyte.String
	if !outerSeq.ReadASN1(&explicit, asn1.Tag(0).ContextSpecific().Constructed()) {
		t.Fatal("no explicit [0]")
	}
	var sd cryptobyte.String
	if !explicit.ReadASN1(&sd, asn1.SEQUENCE) {
		t.Fatal("no SignedData")
	}

	// SignedData ::= version, digestAlgorithms, encapContentInfo,
	// certificates[0]?, crls[1]?, signerInfos SET. Capture each leading
	// element as a raw TLV so it can be copied back verbatim.
	var versionRaw cryptobyte.String
	if !sd.ReadASN1Element(&versionRaw, asn1.INTEGER) {
		t.Fatal("no version")
	}
	var digestAlgsRaw cryptobyte.String
	if !sd.ReadASN1Element(&digestAlgsRaw, asn1.SET) {
		t.Fatal("no digestAlgs")
	}
	var encapRaw cryptobyte.String
	if !sd.ReadASN1Element(&encapRaw, asn1.SEQUENCE) {
		t.Fatal("no encapContentInfo")
	}
	// Capture optional certificates [0] and CRLs [1] verbatim.
	var optional []byte
	for !(sd.PeekASN1Tag(asn1.SET)) {
		if sd.Empty() {
			t.Fatal("never reached SignerInfos SET")
		}
		var raw cryptobyte.String
		switch {
		case sd.PeekASN1Tag(asn1.Tag(0).ContextSpecific().Constructed()):
			if !sd.ReadASN1Element(&raw, asn1.Tag(0).ContextSpecific().Constructed()) {
				t.Fatal("failed reading certificates [0]")
			}
		case sd.PeekASN1Tag(asn1.Tag(1).ContextSpecific().Constructed()):
			if !sd.ReadASN1Element(&raw, asn1.Tag(1).ContextSpecific().Constructed()) {
				t.Fatal("failed reading CRLs [1]")
			}
		default:
			t.Fatalf("unexpected tag before SignerInfos SET: 0x%x", []byte(sd)[0])
		}
		optional = append(optional, raw...)
	}
	var signerInfos cryptobyte.String
	if !sd.ReadASN1(&signerInfos, asn1.SET) {
		t.Fatal("no signerInfos")
	}
	if !sd.Empty() {
		t.Fatalf("unexpected trailing SignedData bytes: %d", len(sd))
	}

	var firstSigner cryptobyte.String
	if !signerInfos.ReadASN1Element(&firstSigner, asn1.SEQUENCE) {
		t.Fatal("no first signerInfo")
	}
	if !signerInfos.Empty() {
		t.Skip("test fixture already has multiple signers")
	}
	signerBytes := []byte(firstSigner)

	var out cryptobyte.Builder
	out.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(outerOID)
		b.AddASN1(asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddBytes(versionRaw)
				b.AddBytes(digestAlgsRaw)
				b.AddBytes(encapRaw)
				if len(optional) > 0 {
					b.AddBytes(optional)
				}
				b.AddASN1(asn1.SET, func(b *cryptobyte.Builder) {
					b.AddBytes(signerBytes)
					b.AddBytes(signerBytes)
				})
			})
		})
	})
	return out.BytesOrPanic()
}

func TestParsePKCS7RejectsTrailingBytes(t *testing.T) {
	cert, key := certtest.MkCert(t)
	b, err := SignPKCS7(key, cert, OIDData, []byte{0x00, 0x01})
	if err != nil {
		t.Fatalf("SignPKCS7: %v", err)
	}

	// Bytes appended after the outer ContentInfo are outside every signed
	// structure and must be rejected.
	forged := bytes.Clone(b)
	forged = append(forged, 0x41, 0x42, 0x43)

	if _, err := ParsePKCS7(forged); !errors.Is(err, ErrTrailingData) {
		t.Fatalf("expected ErrTrailingData, got: %v", err)
	}
}

func TestParsePKCS7RejectsTruncatedBlob(t *testing.T) {
	cert, key := certtest.MkCert(t)
	b, err := SignPKCS7(key, cert, OIDData, []byte{0x00, 0x01})
	if err != nil {
		t.Fatalf("SignPKCS7: %v", err)
	}
	if _, err := ParsePKCS7(b[:len(b)-2]); err == nil {
		t.Fatalf("expected truncated PKCS#7 to be rejected")
	}
}

func TestParsePKCS7RejectsMultipleSigners(t *testing.T) {
	cert, key := certtest.MkCert(t)
	b, err := SignPKCS7(key, cert, OIDData, []byte{0x00, 0x01})
	if err != nil {
		t.Fatalf("SignPKCS7: %v", err)
	}
	forged := duplicateSignerInfo(t, b)
	if _, err := ParsePKCS7(forged); !errors.Is(err, ErrMultipleSigners) {
		t.Fatalf("expected ErrMultipleSigners, got: %v", err)
	}
}

func TestParseContentInfoRejectsInnerTrailingData(t *testing.T) {
	// A ContentInfo SEQUENCE with an extra element after OID + [0] content.
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(OIDData)
		b.AddASN1(asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			b.AddASN1OctetString([]byte{0x01})
		})
		b.AddASN1Boolean(true) // unexpected extra field
	})
	der := cryptobyte.String(b.BytesOrPanic())
	if _, _, err := ParseContentInfo(&der); !errors.Is(err, ErrTrailingData) {
		t.Fatalf("expected ErrTrailingData, got: %v", err)
	}
}

func TestVerifyFailsWithNoAuthenticatedAttributes(t *testing.T) {
	cert, key := certtest.MkCert(t)

	// NoAttr produces a SignerInfo without authenticatedAttributes. Verify
	// must fail with the recognizable error rather than a nil dereference.
	b, err := SignPKCS7(key, cert, OIDData, []byte{0x01}, NoAttr())
	if err != nil {
		t.Fatalf("SignPKCS7: %v", err)
	}
	p, err := ParsePKCS7(b)
	if err != nil {
		t.Fatalf("ParsePKCS7: %v", err)
	}
	if _, err := p.Verify(cert); !errors.Is(err, ErrNoAuthenticatedAttributes) {
		t.Fatalf("expected ErrNoAuthenticatedAttributes, got: %v", err)
	}
}

func TestParseAlgorithmIdentifierRejectsExtraParameter(t *testing.T) {
	// SEQUENCE { OID, NULL, NULL } — a second parameter element is invalid.
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(OIDDigestAlgorithmSHA256)
		b.AddASN1NULL()
		b.AddASN1NULL()
	})
	der := cryptobyte.String(b.BytesOrPanic())
	if _, err := ParseAlgorithmIdentifier(&der); !errors.Is(err, ErrTrailingData) {
		t.Fatalf("expected ErrTrailingData, got: %v", err)
	}
}
