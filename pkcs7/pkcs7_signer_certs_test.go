package pkcs7

import (
	"crypto"
	"testing"

	"github.com/foxboron/go-uefi/internal/certtest"
)

func TestSignerCertificates(t *testing.T) {
	key, cert, additionalCerts := certtest.MkCertChain(t)

	h := crypto.SHA256.New()
	h.Write([]byte("test data"))
	content := h.Sum(nil)

	sig, err := SignPKCS7(key, cert, OIDData, content, WithAdditionalCerts(additionalCerts))
	if err != nil {
		t.Fatalf("failed signing: %v", err)
	}

	p7, err := ParsePKCS7(sig)
	if err != nil {
		t.Fatalf("failed parsing PKCS7: %v", err)
	}

	got := p7.SignerCertificates()
	if len(got) != 1 {
		t.Fatalf("expected 1 signer certificate, got %d", len(got))
	}
	if !got[0].Equal(cert) {
		t.Fatalf("returned certificate is not the signing (leaf) certificate")
	}
}

func TestSignerCertificatesNoCerts(t *testing.T) {
	key, cert, additionalCerts := certtest.MkCertChain(t)

	h := crypto.SHA256.New()
	h.Write([]byte("test data"))
	content := h.Sum(nil)

	sig, err := SignPKCS7(key, cert, OIDData, content, NoCerts(), WithAdditionalCerts(additionalCerts))
	if err != nil {
		t.Fatalf("failed signing: %v", err)
	}

	p7, err := ParsePKCS7(sig)
	if err != nil {
		t.Fatalf("failed parsing PKCS7: %v", err)
	}

	if got := p7.SignerCertificates(); len(got) != 0 {
		t.Fatalf("expected no signer certificates without an embedded certificate set, got %d", len(got))
	}
}
