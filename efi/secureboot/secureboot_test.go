package secureboot

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"os"
	"testing"

	"github.com/foxboron/go-uefi/authenticode"
	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/go-uefi/efi/util"
	"github.com/foxboron/go-uefi/internal/certtest"
	"github.com/foxboron/go-uefi/pkcs7"
)

var zeroOwner = util.EFIGUID{}

const peFixture = "../../authenticode/testdata/test.pecoff"

type imageSigner struct {
	key             crypto.Signer
	cert            *x509.Certificate
	additionalCerts []*x509.Certificate
}

// signImage parses the fixture and signs it with the supplied signers.
func signImage(t *testing.T, signers ...imageSigner) *authenticode.PECOFFBinary {
	t.Helper()
	raw, err := os.ReadFile(peFixture)
	if err != nil {
		t.Fatalf("failed reading fixture: %v", err)
	}
	binary, err := authenticode.Parse(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("failed parsing fixture: %v", err)
	}
	for _, s := range signers {
		var opts []pkcs7.Option
		if len(s.additionalCerts) > 0 {
			opts = append(opts, pkcs7.WithAdditionalCerts(s.additionalCerts))
		}
		if _, err := binary.Sign(s.key, s.cert, opts...); err != nil {
			t.Fatalf("failed signing image: %v", err)
		}
	}
	reparsed, err := authenticode.Parse(bytes.NewReader(binary.Bytes()))
	if err != nil {
		t.Fatalf("failed re-parsing signed image: %v", err)
	}
	return reparsed
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed reading %s: %v", path, err)
	}
	return b
}

// certDatabase builds a database containing X509 entries for the given certs,
// all merged into a single signature list.
func certDatabase(certs ...*x509.Certificate) *signature.SignatureDatabase {
	sd := signature.NewSignatureDatabase()
	for _, cert := range certs {
		if err := sd.Append(signature.CERT_X509_GUID, zeroOwner, cert.Raw); err != nil {
			panic(err)
		}
	}
	return sd
}

// certDatabaseSplit is like certDatabase but places every certificate in its
// own signature list, exercising a different on-wire encoding.
func certDatabaseSplit(certs ...*x509.Certificate) *signature.SignatureDatabase {
	sd := signature.NewSignatureDatabase()
	for _, cert := range certs {
		sl := signature.NewSignatureList(signature.CERT_X509_GUID)
		if err := sl.AppendBytes(zeroOwner, cert.Raw); err != nil {
			panic(err)
		}
		sd.AppendList(sl)
	}
	return sd
}

// certDatabaseReversed stores the certificates in reverse order in one list.
func certDatabaseReversed(certs ...*x509.Certificate) *signature.SignatureDatabase {
	sd := signature.NewSignatureDatabase()
	for i := len(certs) - 1; i >= 0; i-- {
		if err := sd.Append(signature.CERT_X509_GUID, zeroOwner, certs[i].Raw); err != nil {
			panic(err)
		}
	}
	return sd
}

func hashDatabase(hashes ...[]byte) *signature.SignatureDatabase {
	sd := signature.NewSignatureDatabase()
	for _, h := range hashes {
		if err := sd.Append(signature.CERT_SHA256_GUID, zeroOwner, h); err != nil {
			panic(err)
		}
	}
	return sd
}

func chainFixture(t *testing.T) (crypto.Signer, *x509.Certificate, *x509.Certificate, *x509.Certificate) {
	t.Helper()
	leafKey, leaf, chain := certtest.MkCertChain(t)
	intermediate, root := chain[0], chain[1]
	return leafKey, leaf, intermediate, root
}

func TestVerifyImage(t *testing.T) {
	leafKey, leaf, intermediate, root := chainFixture(t)
	otherKey, otherCert := certtest.MkSelfSignedCert(t)

	signed := signImage(t, imageSigner{
		key:             leafKey,
		cert:            leaf,
		additionalCerts: []*x509.Certificate{intermediate, root},
	})

	imageHash := signed.Hash(crypto.SHA256)

	// An independent image signed by an unrelated, untrusted key.
	untrusted := signImage(t, imageSigner{key: otherKey, cert: otherCert})

	unsigned, err := authenticode.Parse(bytes.NewReader(mustReadFile(t, peFixture)))
	if err != nil {
		t.Fatalf("failed parsing fixture: %v", err)
	}

	cases := []struct {
		name    string
		binary  *authenticode.PECOFFBinary
		db      *signature.SignatureDatabase
		dbx     *signature.SignatureDatabase
		wantOK  bool
		wantErr error
	}{
		{
			name:    "unsigned image is denied",
			binary:  unsigned,
			db:      certDatabase(root),
			wantOK:  false,
			wantErr: ErrNoSignatures,
		},
		{
			name:   "chain to trusted root in db is authorized",
			binary: signed,
			db:     certDatabase(root),
			wantOK: true,
		},
		{
			name:   "chain to trusted intermediate in db is authorized",
			binary: signed,
			db:     certDatabase(intermediate),
			wantOK: true,
		},
		{
			name:   "leaf directly trusted in db is authorized",
			binary: signed,
			db:     certDatabase(leaf),
			wantOK: true,
		},
		{
			name:    "untrusted signer is denied",
			binary:  untrusted,
			db:      certDatabase(root),
			wantOK:  false,
			wantErr: ErrNoAuthorizedSignature,
		},
		{
			name:    "empty db denies a valid signature",
			binary:  signed,
			db:      signature.NewSignatureDatabase(),
			wantOK:  false,
			wantErr: ErrNoAuthorizedSignature,
		},
		{
			name:    "nil databases are treated as empty",
			binary:  signed,
			wantOK:  false,
			wantErr: ErrNoAuthorizedSignature,
		},
		{
			name:    "image hash in dbx denies even with trusted chain in db",
			binary:  signed,
			db:      certDatabase(root),
			dbx:     hashDatabase(imageHash),
			wantOK:  false,
			wantErr: ErrImageHashDenied,
		},
		{
			name:    "revoked intermediate cert in dbx denies despite trusted root",
			binary:  signed,
			db:      certDatabase(root),
			dbx:     certDatabase(intermediate),
			wantOK:  false,
			wantErr: ErrCertRevoked,
		},
		{
			name:    "revoked leaf cert in dbx denies despite trusted root",
			binary:  signed,
			db:      certDatabase(root),
			dbx:     certDatabase(leaf),
			wantOK:  false,
			wantErr: ErrCertRevoked,
		},
		{
			name:   "image hash in db is authorized without signature trust",
			binary: untrusted,
			db:     hashDatabase(untrusted.Hash(crypto.SHA256)),
			wantOK: true,
		},
		{
			name:    "dbx hash beats db hash authorization",
			binary:  untrusted,
			db:      hashDatabase(imageHash),
			dbx:     hashDatabase(untrusted.Hash(crypto.SHA256)),
			wantOK:  false,
			wantErr: ErrImageHashDenied,
		},
		{
			name:   "unrelated extra entries in db do not disturb a trusted chain",
			binary: signed,
			db:     certDatabase(root, otherCert),
			wantOK: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := VerifyImage(tc.binary, tc.db, tc.dbx)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (err: %v)", ok, tc.wantOK, err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr == nil && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestVerifyImageMultiSignature(t *testing.T) {
	leafKey, leaf, intermediate, root := chainFixture(t)
	otherKey, otherCert := certtest.MkSelfSignedCert(t)

	// Image carrying two independent signatures.
	multi := signImage(t,
		imageSigner{
			key:             leafKey,
			cert:            leaf,
			additionalCerts: []*x509.Certificate{intermediate, root},
		},
		imageSigner{key: otherKey, cert: otherCert},
	)

	sigs, err := multi.Signatures()
	if err != nil {
		t.Fatalf("failed reading signatures: %v", err)
	}
	if len(sigs) != 2 {
		t.Fatalf("expected 2 signatures, got %d", len(sigs))
	}

	t.Run("one trusted signature authorizes", func(t *testing.T) {
		ok, err := VerifyImage(multi, certDatabase(root), nil)
		if err != nil || !ok {
			t.Fatalf("expected admission, got ok=%v err=%v", ok, err)
		}
	})

	t.Run("the other trusted signature also authorizes", func(t *testing.T) {
		ok, err := VerifyImage(multi, certDatabase(otherCert), nil)
		if err != nil || !ok {
			t.Fatalf("expected admission, got ok=%v err=%v", ok, err)
		}
	})

	t.Run("revoked certificate on one signature is overridden by a trusted second signature", func(t *testing.T) {
		ok, err := VerifyImage(multi, certDatabase(otherCert), certDatabase(leaf))
		if err != nil || !ok {
			t.Fatalf("expected admission through the unrevoked signature, got ok=%v err=%v", ok, err)
		}
	})

	t.Run("all signatures revoked denies", func(t *testing.T) {
		ok, err := VerifyImage(multi, certDatabase(root, otherCert), certDatabase(leaf, otherCert))
		if ok || !errors.Is(err, ErrCertRevoked) {
			t.Fatalf("expected ErrCertRevoked, got ok=%v err=%v", ok, err)
		}
	})

	t.Run("neither signature trusted denies", func(t *testing.T) {
		ok, err := VerifyImage(multi, signature.NewSignatureDatabase(), nil)
		if ok || !errors.Is(err, ErrNoAuthorizedSignature) {
			t.Fatalf("expected ErrNoAuthorizedSignature, got ok=%v err=%v", ok, err)
		}
	})
}

func TestVerifyImageOrderAndEncodingIndependent(t *testing.T) {
	leafKey, leaf, intermediate, root := chainFixture(t)
	signed := signImage(t, imageSigner{
		key:             leafKey,
		cert:            leaf,
		additionalCerts: []*x509.Certificate{intermediate, root},
	})

	imageHash := signed.Hash(crypto.SHA256)

	// The same logical db policy expressed three different ways.
	dbVariants := []*signature.SignatureDatabase{
		certDatabase(root, intermediate, leaf),
		certDatabaseSplit(root, intermediate, leaf),
		certDatabaseReversed(root, intermediate, leaf),
	}
	// The same logical dbx policy expressed three different ways.
	dbxVariants := []*signature.SignatureDatabase{
		hashDatabase(imageHash),
		certDatabase(intermediate),
		certDatabaseSplit(intermediate),
	}

	for i, db := range dbVariants {
		ok, err := VerifyImage(signed, db, nil)
		if !ok || err != nil {
			t.Fatalf("db variant %d: expected admission, got ok=%v err=%v", i, ok, err)
		}
	}

	for i, dbx := range dbxVariants {
		ok, err := VerifyImage(signed, certDatabase(root), dbx)
		if ok {
			t.Fatalf("dbx variant %d: expected denial, got admission", i)
		}
		if i == 0 && !errors.Is(err, ErrImageHashDenied) {
			t.Fatalf("dbx variant %d: expected ErrImageHashDenied, got %v", i, err)
		}
		if i > 0 && !errors.Is(err, ErrCertRevoked) {
			t.Fatalf("dbx variant %d: expected ErrCertRevoked, got %v", i, err)
		}
	}

	// Shuffling list order inside the database must not change the verdict.
	db := certDatabaseSplit(root, intermediate, leaf)
	(*db)[0], (*db)[1], (*db)[2] = (*db)[2], (*db)[0], (*db)[1]
	ok, err := VerifyImage(signed, db, nil)
	if !ok || err != nil {
		t.Fatalf("shuffled db: expected admission, got ok=%v err=%v", ok, err)
	}
}

func TestVerifyImageSerializedRoundTrip(t *testing.T) {
	leafKey, leaf, intermediate, root := chainFixture(t)
	signed := signImage(t, imageSigner{
		key:             leafKey,
		cert:            leaf,
		additionalCerts: []*x509.Certificate{intermediate, root},
	})

	// Serialize the databases as EFI signature lists (the on-disk/on-wire
	// encoding of db/dbx) and parse them back, to ensure the verdict depends on
	// the encoded entries rather than any in-memory structure.
	dbBytes := certDatabase(root).Bytes()
	parsedDB, err := signature.ReadSignatureDatabase(bytes.NewReader(dbBytes))
	if err != nil {
		t.Fatalf("failed re-parsing db: %v", err)
	}
	db := &parsedDB

	dbxBytes := certDatabase(intermediate).Bytes()
	parsedDBX, err := signature.ReadSignatureDatabase(bytes.NewReader(dbxBytes))
	if err != nil {
		t.Fatalf("failed re-parsing dbx: %v", err)
	}
	dbx := &parsedDBX

	if ok, err := VerifyImage(signed, db, nil); !ok || err != nil {
		t.Fatalf("round-tripped db: expected admission, got ok=%v err=%v", ok, err)
	}
	if ok, err := VerifyImage(signed, db, dbx); ok || !errors.Is(err, ErrCertRevoked) {
		t.Fatalf("round-tripped dbx: expected ErrCertRevoked, got ok=%v err=%v", ok, err)
	}
}

func TestVerifyImageDeterministicAcrossRuns(t *testing.T) {
	leafKey, leaf, intermediate, root := chainFixture(t)
	signed := signImage(t, imageSigner{
		key:             leafKey,
		cert:            leaf,
		additionalCerts: []*x509.Certificate{intermediate, root},
	})
	db := certDatabase(root)
	dbx := certDatabase(intermediate)

	// Repeating the identical evaluation must always return the identical
	// verdict, for both an allow and a deny decision.
	for i := 0; i < 5; i++ {
		if ok, err := VerifyImage(signed, db, nil); !ok || err != nil {
			t.Fatalf("run %d allow: unstable result ok=%v err=%v", i, ok, err)
		}
		if ok, err := VerifyImage(signed, db, dbx); ok || !errors.Is(err, ErrCertRevoked) {
			t.Fatalf("run %d deny: unstable result ok=%v err=%v", i, ok, err)
		}
	}
}

func TestVerifyImageEmbeddedCertOrderIndependent(t *testing.T) {
	leafKey, leaf, intermediate, root := chainFixture(t)

	// The embedded chain is deliberately stored root-first, which is the
	// opposite of the usual leaf-first ordering.
	reversed := signImage(t, imageSigner{
		key:             leafKey,
		cert:            leaf,
		additionalCerts: []*x509.Certificate{root, intermediate},
	})

	for i, db := range []*signature.SignatureDatabase{
		certDatabase(root),
		certDatabase(intermediate),
		certDatabase(leaf),
	} {
		ok, err := VerifyImage(reversed, db, nil)
		if !ok || err != nil {
			t.Fatalf("db variant %d with reversed embedded chain: expected admission, got ok=%v err=%v", i, ok, err)
		}
	}
}

func TestVerifyImageBrokenChain(t *testing.T) {
	leafKey, leaf, intermediate, root := chainFixture(t)
	_, foreignLeaf, _, _ := chainFixture(t)

	signed := signImage(t, imageSigner{
		key:             leafKey,
		cert:            leaf,
		additionalCerts: []*x509.Certificate{intermediate, root},
	})

	// Trusting a leaf from an unrelated chain must not authorize the image.
	ok, err := VerifyImage(signed, certDatabase(foreignLeaf), nil)
	if ok || !errors.Is(err, ErrNoAuthorizedSignature) {
		t.Fatalf("expected ErrNoAuthorizedSignature, got ok=%v err=%v", ok, err)
	}

	// A trusted db cannot rescue a signature that no longer validates: tampering
	// with the image body breaks its Authenticode digest.
	tampered := bytes.Clone(signed.Bytes())
	if len(tampered) < 0x300 {
		t.Fatalf("fixture too small to tamper: %d bytes", len(tampered))
	}
	tampered[0x300] ^= 0xff
	bad, parseErr := authenticode.Parse(bytes.NewReader(tampered))
	if parseErr != nil {
		t.Skipf("tampered image unparseable: %v", parseErr)
	}
	ok, err = VerifyImage(bad, certDatabase(root), nil)
	if ok {
		t.Fatalf("tampered image admitted: %v", err)
	}
}

func TestVerifyImageReader(t *testing.T) {
	leafKey, leaf, intermediate, root := chainFixture(t)
	signed := signImage(t, imageSigner{
		key:             leafKey,
		cert:            leaf,
		additionalCerts: []*x509.Certificate{intermediate, root},
	})

	ok, err := VerifyImageReader(bytes.NewReader(signed.Bytes()), certDatabase(root), nil)
	if err != nil || !ok {
		t.Fatalf("expected admission through reader, got ok=%v err=%v", ok, err)
	}
}
