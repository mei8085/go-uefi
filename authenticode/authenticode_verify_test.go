package authenticode

import (
	"bytes"
	"crypto"
	"testing"

	"github.com/foxboron/go-uefi/internal/certtest"
)

func TestVerifyAuthenticodeSingleSignature(t *testing.T) {
	cert, key := certtest.MkCert(t)
	binary := mustParse(t, "testdata/test.pecoff")

	if _, err := binary.Sign(key, cert); err != nil {
		t.Fatalf("failed signing binary: %v", err)
	}

	signed, err := Parse(bytes.NewReader(binary.Bytes()))
	if err != nil {
		t.Fatalf("failed re-parsing binary: %v", err)
	}

	valid, err := signed.VerifyAuthenticode()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(valid) != 1 {
		t.Fatalf("expected 1 valid signature, got %d", len(valid))
	}
}

func TestVerifyAuthenticodeMultiSignature(t *testing.T) {
	cert1, key1 := certtest.MkCert(t)
	cert2, key2 := certtest.MkCert(t)
	binary := mustParse(t, "testdata/test.pecoff")

	if _, err := binary.Sign(key1, cert1); err != nil {
		t.Fatalf("failed first signing: %v", err)
	}
	if _, err := binary.Sign(key2, cert2); err != nil {
		t.Fatalf("failed second signing: %v", err)
	}

	signed, err := Parse(bytes.NewReader(binary.Bytes()))
	if err != nil {
		t.Fatalf("failed re-parsing binary: %v", err)
	}

	valid, err := signed.VerifyAuthenticode()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(valid) != 2 {
		t.Fatalf("expected 2 valid signatures, got %d", len(valid))
	}
}

func TestVerifyAuthenticodeUnsigned(t *testing.T) {
	binary := mustParse(t, "testdata/test.pecoff")

	valid, err := binary.VerifyAuthenticode()
	if err != ErrNoSignatures {
		t.Fatalf("expected ErrNoSignatures, got %v", err)
	}
	if valid != nil {
		t.Fatalf("expected nil result for unsigned image, got %v", valid)
	}
}

func TestVerifyAuthenticodeForgedSignatureSkipped(t *testing.T) {
	cert, key := certtest.MkCert(t)

	original := mustParse(t, "testdata/test.pecoff")
	sig, err := original.Sign(key, cert)
	if err != nil {
		t.Fatal(err)
	}

	// Graft the valid signature from original onto a different image, producing
	// a signature whose authenticated digest no longer matches.
	fake := mustParse(t, "../tests/data/binary/HelloWorld.efi")
	forged := bytes.Replace(sig, original.Hash(crypto.SHA256), fake.Hash(crypto.SHA256), 1)
	if bytes.Equal(forged, sig) {
		t.Fatalf("digest not found in signature")
	}
	if err := fake.AppendSignature(forged); err != nil {
		t.Fatalf("failed appending forged signature: %v", err)
	}

	reparsed, err := Parse(bytes.NewReader(fake.Bytes()))
	if err != nil {
		t.Fatal(err)
	}

	valid, err := reparsed.VerifyAuthenticode()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(valid) != 0 {
		t.Fatalf("expected no valid signatures for forged image, got %d", len(valid))
	}
}

func TestVerifyAuthenticodeOneForgedOneValid(t *testing.T) {
	goodCert, goodKey := certtest.MkCert(t)
	badCert, badKey := certtest.MkCert(t)

	original := mustParse(t, "testdata/test.pecoff")
	badSig, err := original.Sign(badKey, badCert)
	if err != nil {
		t.Fatal(err)
	}

	// Forge the first signature onto a different image.
	fake := mustParse(t, "../tests/data/binary/HelloWorld.efi")
	forged := bytes.Replace(badSig, original.Hash(crypto.SHA256), fake.Hash(crypto.SHA256), 1)
	if bytes.Equal(forged, badSig) {
		t.Fatalf("digest not found in signature")
	}
	if err := fake.AppendSignature(forged); err != nil {
		t.Fatalf("failed appending forged signature: %v", err)
	}

	// The good signature is created directly on the target image.
	if _, err := fake.Sign(goodKey, goodCert); err != nil {
		t.Fatalf("failed signing image: %v", err)
	}

	reparsed, err := Parse(bytes.NewReader(fake.Bytes()))
	if err != nil {
		t.Fatal(err)
	}

	valid, err := reparsed.VerifyAuthenticode()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(valid) != 1 {
		t.Fatalf("expected exactly 1 valid signature, got %d", len(valid))
	}
}
