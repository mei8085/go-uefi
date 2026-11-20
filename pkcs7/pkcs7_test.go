package pkcs7

import (
	"crypto"
	"crypto/x509"
	encasn1 "encoding/asn1"
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/foxboron/go-uefi/asntest"
	"github.com/foxboron/go-uefi/internal/certtest"
	"golang.org/x/crypto/cryptobyte"
)

func TestVerifySignature(t *testing.T) {
	cert, key := certtest.MkCert(t)
	// TODO: Introduce negative cases
	for n, c := range []struct {
		t       string
		options []Option
		data    []byte
		oid     encasn1.ObjectIdentifier
	}{
		{
			t:       "Base case",
			options: []Option{},
			data:    []byte{0x00, 0x01},
			oid:     OIDData,
		},
		{
			t:       "All options",
			options: []Option{NoAttr(), NoCerts()},
			data:    []byte{0x00, 0x01},
			oid:     OIDData,
		},
	} {
		t.Run(fmt.Sprintf("%d - %s", n, c.t), func(t *testing.T) {
			b, err := SignPKCS7(key, cert, c.oid, c.data)
			if err != nil {
				t.Fatalf("failed signing: %v", err)
			}
			pkcs, err := ParsePKCS7(b)
			if err != nil {
				t.Fatalf("failed parsing PKCS7 signature: %v", err)
			}

			ok, err := pkcs.Verify(cert)
			if err != nil {
				t.Fatalf("failed verifying signature: %v", err)
			}

			if !ok {
				t.Fatalf("Signature should validate")
			}
		})
	}
}

// Try to parse a signature created by sbvarsign
func TestParseSbvarignSignature(t *testing.T) {
	b, err := os.ReadFile("testdata/test.signed")
	if err != nil {
		t.Fatal(err)
	}

	_, err = ParsePKCS7(b)
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

	b, err := os.ReadFile("testdata/old_pkcs7_implementation.der")
	if err != nil {
		t.Fatal(err)
	}

	img := []byte{0x00, 0x01}
	h := crypto.SHA256.New()
	h.Write(img)
	bb, err := SignPKCS7(key, cert, OIDData, h.Sum(nil))
	if err != nil {
		t.Fatalf("failed signing digest")
	}

	cs := cryptobyte.String(bb)
	_, bytes, err := ParseContentInfo(&cs)
	if err != nil {
		log.Fatal(err)
	}

	// We should see a couple of differences, but largely the same structure should be present
	asntest.Asn1Compare(t, b, bytes)
}

func TestVerifySignatureAlgorithms(t *testing.T) {
	rsaCert, rsaKey := certtest.MkCert(t)
	ecdsaKey, ecdsaCert := certtest.MkSelfSignedECDSACert(t)

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
			data := []byte{0x00, 0x01}
			b, err := SignPKCS7(c.signer, c.cert, OIDData, data, WithDigestAlgorithm(c.hash))
			if err != nil {
				t.Fatalf("failed signing: %v", err)
			}
			pkcs, err := ParsePKCS7(b)
			if err != nil {
				t.Fatalf("failed parsing PKCS7 signature: %v", err)
			}

			if !pkcs.AlgorithmIdentifier.Algorithm.Equal(hashFunctionDigestAlgorithm[c.hash]) {
				t.Fatalf("unexpected digest algorithm in SignedData: %s", pkcs.AlgorithmIdentifier.Algorithm)
			}

			ok, err := pkcs.Verify(c.cert)
			if err != nil {
				t.Fatalf("failed verifying signature: %v", err)
			}
			if !ok {
				t.Fatalf("Signature should validate")
			}
		})
	}
}

func TestSignPKCS7UnsupportedDigestAlgorithm(t *testing.T) {
	cert, key := certtest.MkCert(t)

	if _, err := SignPKCS7(key, cert, OIDData, []byte{0x00}, WithDigestAlgorithm(crypto.SHA1)); err == nil {
		t.Fatalf("expected an error when signing with an unsupported digest algorithm")
	}
}

func TestVerifyRejectsMismatchedKeyAlgorithm(t *testing.T) {
	rsaCert, rsaKey := certtest.MkCert(t)
	ecdsaKey, ecdsaCert := certtest.MkSelfSignedECDSACert(t)

	for _, c := range []struct {
		name        string
		signer      crypto.Signer
		cert        *x509.Certificate
		tamperedOID encasn1.ObjectIdentifier
	}{
		// An RSA signature claiming to be an ECDSA signature
		{"RSA signature with ECDSA algorithm", rsaKey, rsaCert, OIDEncryptionAlgorithmECDSA},
		// An ECDSA signature claiming to be an RSA signature
		{"ECDSA signature with RSA algorithm", ecdsaKey, ecdsaCert, OIDEncryptionAlgorithmRSA},
		// An unknown digest encryption algorithm
		{"RSA signature with unknown algorithm", rsaKey, rsaCert, encasn1.ObjectIdentifier{1, 2, 3, 4}},
	} {
		t.Run(c.name, func(t *testing.T) {
			b, err := SignPKCS7(c.signer, c.cert, OIDData, []byte{0x00, 0x01})
			if err != nil {
				t.Fatalf("failed signing: %v", err)
			}
			pkcs, err := ParsePKCS7(b)
			if err != nil {
				t.Fatalf("failed parsing PKCS7 signature: %v", err)
			}

			pkcs.SignerInfo[0].EncryptedDigestAlgorithm.Algorithm = c.tamperedOID

			ok, err := pkcs.Verify(c.cert)
			if err == nil {
				t.Fatalf("expected an error when the digest encryption algorithm doesn't match the key type")
			}
			if ok {
				t.Fatalf("signature should not validate")
			}
		})
	}
}

func TestVerifyRejectsUnsupportedDigestAlgorithm(t *testing.T) {
	cert, key := certtest.MkCert(t)

	b, err := SignPKCS7(key, cert, OIDData, []byte{0x00, 0x01})
	if err != nil {
		t.Fatalf("failed signing: %v", err)
	}
	pkcs, err := ParsePKCS7(b)
	if err != nil {
		t.Fatalf("failed parsing PKCS7 signature: %v", err)
	}

	// SHA-1 is not a supported digest algorithm
	pkcs.SignerInfo[0].DigestAlgorithm.Algorithm = encasn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}

	ok, err := pkcs.Verify(cert)
	if err == nil {
		t.Fatalf("expected an error when the digest algorithm is unsupported")
	}
	if ok {
		t.Fatalf("signature should not validate")
	}
}
