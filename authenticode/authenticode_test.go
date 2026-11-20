package authenticode

import (
	"bytes"
	"crypto"
	"crypto/x509"
	encasn1 "encoding/asn1"
	"errors"
	"os"
	"testing"

	"github.com/foxboron/go-uefi/asntest"
	"github.com/foxboron/go-uefi/internal/certtest"
	"github.com/foxboron/go-uefi/pkcs7"
)

func TestVerifyAuthenticode(t *testing.T) {
	cert, key := certtest.MkCert(t)

	img := []byte("test")
	b, err := SignAuthenticode(key, cert, bytes.NewReader(img), crypto.SHA256)
	if err != nil {
		t.Fatalf("message")
	}

	auth, err := ParseAuthenticode(b)
	if err != nil {
		t.Fatalf("%v", err)
	}
	ok, err := auth.Verify(cert, bytes.NewReader(img))
	if err != nil {
		t.Fatalf("failed to verify authenticode checksum: %v", err)
	}

	if !ok {
		t.Fatalf("authenticode signature didn't validate, it should")
	}
}

func TestVerifyAuthenticodeAlgorithms(t *testing.T) {
	rsaCert, rsaKey := certtest.MkCert(t)
	ecdsaKey, ecdsaCert := certtest.MkSelfSignedECDSACert(t)

	img := []byte("test")

	for _, c := range []struct {
		name   string
		signer crypto.Signer
		cert   *x509.Certificate
		hash   crypto.Hash
	}{
		{"RSA/SHA-256", rsaKey, rsaCert, crypto.SHA256},
		{"RSA/SHA-384", rsaKey, rsaCert, crypto.SHA384},
		{"RSA/SHA-512", rsaKey, rsaCert, crypto.SHA512},
		{"ECDSA/SHA-256", ecdsaKey, ecdsaCert, crypto.SHA256},
		{"ECDSA/SHA-384", ecdsaKey, ecdsaCert, crypto.SHA384},
		{"ECDSA/SHA-512", ecdsaKey, ecdsaCert, crypto.SHA512},
	} {
		t.Run(c.name, func(t *testing.T) {
			b, err := SignAuthenticode(c.signer, c.cert, bytes.NewReader(img), c.hash)
			if err != nil {
				t.Fatalf("failed signing: %v", err)
			}

			auth, err := ParseAuthenticode(b)
			if err != nil {
				t.Fatalf("failed parsing authenticode: %v", err)
			}

			ok, err := auth.Verify(c.cert, bytes.NewReader(img))
			if err != nil {
				t.Fatalf("failed to verify authenticode checksum: %v", err)
			}
			if !ok {
				t.Fatalf("authenticode signature didn't validate, it should")
			}
		})
	}
}

func TestVerifyAuthenticodeRejectsMismatchedDigest(t *testing.T) {
	cert, key := certtest.MkCert(t)

	img := []byte("test")
	b, err := SignAuthenticode(key, cert, bytes.NewReader(img), crypto.SHA256)
	if err != nil {
		t.Fatalf("failed signing: %v", err)
	}

	// The digest was made with SHA-256, but the algorithm identifier claims
	// SHA-384. The digest length doesn't match the algorithm and has to be
	// rejected.
	auth, err := ParseAuthenticode(b)
	if err != nil {
		t.Fatalf("failed parsing authenticode: %v", err)
	}
	auth.Algid.Algorithm = pkcs7.OIDDigestAlgorithmSHA384

	ok, err := auth.Verify(cert, bytes.NewReader(img))
	if err == nil || err.Error() != "wrong block size" {
		t.Fatalf("expected 'wrong block size' error, got: %v", err)
	}
	if ok {
		t.Fatalf("authenticode signature should not validate")
	}

	// An unsupported digest algorithm has to be rejected as well.
	auth, err = ParseAuthenticode(b)
	if err != nil {
		t.Fatalf("failed parsing authenticode: %v", err)
	}
	// SHA-1
	auth.Algid.Algorithm = encasn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}

	ok, err = auth.Verify(cert, bytes.NewReader(img))
	if err == nil || err.Error() != "unsupported hashing function" {
		t.Fatalf("expected 'unsupported hashing function' error, got: %v", err)
	}
	if ok {
		t.Fatalf("authenticode signature should not validate")
	}
}

func TestSignAuthenticodeUnsupportedHash(t *testing.T) {
	cert, key := certtest.MkCert(t)

	if _, err := SignAuthenticode(key, cert, bytes.NewReader([]byte("test")), crypto.SHA1); err == nil {
		t.Fatalf("expected an error when signing with an unsupported digest algorithm")
	}
}

func TestSignVerifyPECOFFAlgorithms(t *testing.T) {
	rsaCert, rsaKey := certtest.MkCert(t)
	ecdsaKey, ecdsaCert := certtest.MkSelfSignedECDSACert(t)

	for _, c := range []struct {
		name   string
		signer crypto.Signer
		cert   *x509.Certificate
		hash   crypto.Hash
	}{
		{"RSA/SHA-384", rsaKey, rsaCert, crypto.SHA384},
		{"RSA/SHA-512", rsaKey, rsaCert, crypto.SHA512},
		{"ECDSA/SHA-256", ecdsaKey, ecdsaCert, crypto.SHA256},
		{"ECDSA/SHA-384", ecdsaKey, ecdsaCert, crypto.SHA384},
		{"ECDSA/SHA-512", ecdsaKey, ecdsaCert, crypto.SHA512},
	} {
		t.Run(c.name, func(t *testing.T) {
			pe := mustParse(t, "testdata/test.pecoff")

			if _, err := pe.SignWithHash(c.signer, c.cert, c.hash); err != nil {
				t.Fatalf("failed signing binary: %v", err)
			}

			ok, err := pe.Verify(c.cert)
			if err != nil {
				t.Fatalf("failed verify binary: %v", err)
			}
			if !ok {
				t.Fatalf("failed verify binary, not ok")
			}

			// Verify the serialized binary as well
			reparsed, err := Parse(bytes.NewReader(pe.Bytes()))
			if err != nil {
				t.Fatalf("failed parsing signed binary: %v", err)
			}
			ok, err = reparsed.Verify(c.cert)
			if err != nil {
				t.Fatalf("failed verify reparsed binary: %v", err)
			}
			if !ok {
				t.Fatalf("failed verify reparsed binary, not ok")
			}
		})
	}
}

func TestParseSbsign(t *testing.T) {
	b, err := os.ReadFile("testdata/test.authenticode.signed")
	if err != nil {
		t.Fatal(err)
	}

	_, err = ParseAuthenticode(b)
	if err != nil {
		t.Fatalf("failed to parse pkcs7: %v", err)
	}
}

// This test compares the library ASN.1 output to the old implementation
// This is mostly for debugging the implementation.
func TestCompareOldImplementation(t *testing.T) {
	if !testing.Verbose() {
		return
	}
	cert, key := certtest.MkCert(t)

	b, err := os.ReadFile("testdata/old_authenticode_implementation.der")
	if err != nil {
		t.Fatal(err)
	}

	img := []byte{0x00, 0x01}
	bb, err := SignAuthenticode(key, cert, bytes.NewReader(img), crypto.SHA256)
	if err != nil {
		t.Fatalf("failed signing digest")
	}

	// We should see a couple of differences, but largely the same structure should be present
	asntest.Asn1Compare(t, b, bb)
}

func TestCheckForgedSignature(t *testing.T) {
	cert, key := certtest.MkCert(t)

	// The binary we intend to sign
	original := mustParse(t, "testdata/test.pecoff")
	sig, err := original.Sign(key, cert)
	if err != nil {
		t.Fatal(err)
	}

	// We graft the above valid signature on to this binary
	fake := mustParse(t, "../tests/data/binary/HelloWorld.efi")

	forged := bytes.Replace(sig, original.Hash(crypto.SHA256), fake.Hash(crypto.SHA256), 1)
	if bytes.Equal(forged, sig) {
		t.Fatalf("digest not found in signature")
	}
	if err := fake.AppendSignature(forged); err != nil {
		t.Fatalf("failed to append the signature ontop of the forged binary")
	}

	reparsed, err := Parse(bytes.NewReader(fake.Bytes()))
	if err != nil {
		t.Fatal(err)
	}

	ok, err := reparsed.Verify(cert)
	if ok {
		t.Fatal("go-uefi accepts a forged sinature")
	}

	// Check for other errors
	if !errors.Is(err, ErrNoValidSignatures) {
		t.Fatal(err)
	}
}
