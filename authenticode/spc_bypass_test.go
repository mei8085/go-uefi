package authenticode

import (
	"bytes"
	"crypto"
	"errors"
	"testing"

	"github.com/foxboron/go-uefi/internal/certtest"
	"github.com/foxboron/go-uefi/pkcs7"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// signRawAuthenticode returns a valid DER Authenticode signature.
func signRawAuthenticode(t *testing.T) []byte {
	t.Helper()
	cert, key := certtest.MkCert(t)
	der, err := SignAuthenticode(key, cert, bytes.NewReader([]byte("test image")), crypto.SHA256)
	if err != nil {
		t.Fatalf("SignAuthenticode: %v", err)
	}
	return der
}

func TestParseAuthenticodeRejectsTrailingSpcData(t *testing.T) {
	der := signRawAuthenticode(t)

	// Append bytes after the outermost PKCS#7 ContentInfo. They are outside
	// every signed structure.
	forged := bytes.Clone(der)
	forged = append(forged, 0x01, 0x02, 0x03)
	if _, err := ParseAuthenticode(forged); err == nil {
		t.Fatalf("expected trailing outer bytes to be rejected")
	}
}

func TestParseAuthenticodeRejectsTrailingBytesInsideIndirectData(t *testing.T) {
	// Construct an SPC_INDIRECT_DATA SEQUENCE with a third, unsigned trailing
	// element after the legitimate SpcAttributeTypeAndOptionalValue and
	// DigestInfo. The strict parser must reject the extra element rather than
	// ignore it.
	var spcOuter cryptobyte.Builder
	spcOuter.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(OIDSpcPEImageDataObjID)
			b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1BitString(nil)
				b.AddASN1(asn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
					b.AddASN1(asn1.Tag(2).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
						b.AddASN1(asn1.Tag(0).ContextSpecific(), func(b *cryptobyte.Builder) {
							b.AddBytes([]byte{0, 0})
						})
					})
				})
			})
		})
		b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(pkcs7.OIDDigestAlgorithmSHA256)
				b.AddASN1NULL()
			})
			b.AddASN1OctetString(make([]byte, 32))
		})
		b.AddASN1OctetString([]byte("unsigned bypass"))
	})

	// Frame the poisoned SPC content in a full PKCS#7 wrapper so it reaches
	// ParseAuthenticode's SPC-level checks.
	cert, key := certtest.MkCert(t)
	blob, err := pkcs7.SignPKCS7(key, cert, OIDSpcIndirectDataContent, spcOuter.BytesOrPanic())
	if err != nil {
		t.Fatalf("SignPKCS7: %v", err)
	}
	_, err = ParseAuthenticode(blob)
	if err == nil {
		t.Fatalf("expected poisoned SPC_INDIRECT_DATA to be rejected")
	}
	if !errors.Is(err, ErrMalformedSpcIndirectData) {
		t.Fatalf("expected ErrMalformedSpcIndirectData, got: %v", err)
	}
}

func TestVerifyReturnsDigestMismatch(t *testing.T) {
	cert, key := certtest.MkCert(t)

	img := []byte("the real image bytes")
	der, err := SignAuthenticode(key, cert, bytes.NewReader(img), crypto.SHA256)
	if err != nil {
		t.Fatalf("SignAuthenticode: %v", err)
	}
	auth, err := ParseAuthenticode(der)
	if err != nil {
		t.Fatalf("ParseAuthenticode: %v", err)
	}

	// A different image must fail with the identifiable digest mismatch.
	tampered := []byte("the real image BYTES")
	ok, err := auth.Verify(cert, bytes.NewReader(tampered))
	if ok {
		t.Fatalf("tampered image verified")
	}
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("expected ErrDigestMismatch, got: %v", err)
	}
}

func TestParseAuthenticodeAcceptsValidSignature(t *testing.T) {
	der := signRawAuthenticode(t)
	auth, err := ParseAuthenticode(der)
	if err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	if len(auth.Digest) == 0 {
		t.Fatalf("parsed signature has no digest")
	}
}
