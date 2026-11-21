package signature

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/foxboron/go-uefi/efi/attributes"
	"github.com/foxboron/go-uefi/efi/util"
	"github.com/foxboron/go-uefi/efivar"
	"github.com/foxboron/go-uefi/internal/certtest"
	"github.com/foxboron/go-uefi/pkcs7"
)

var testOwnerGUID = util.StringToGUID("aabbccdd-eeff-0011-2233-445566778899")

// mkTestDatabase builds a signature database holding the given certificates
// as EFI_CERT_X509_GUID entries.
func mkTestDatabase(t *testing.T, certs ...*x509.Certificate) *SignatureDatabase {
	t.Helper()
	db := NewSignatureDatabase()
	for _, cert := range certs {
		if err := db.Append(CERT_X509_GUID, *testOwnerGUID, cert.Raw); err != nil {
			t.Fatalf("failed appending certificate to database: %v", err)
		}
	}
	return db
}

// testKeys holds the key material for a test secure boot hierarchy.
type testKeys struct {
	pkKey   *rsa.PrivateKey
	pkCert  *x509.Certificate
	kekKey  *rsa.PrivateKey
	kekCert *x509.Certificate
	dbKey   *rsa.PrivateKey
	dbCert  *x509.Certificate
}

func mkTestKeys(t *testing.T) *testKeys {
	t.Helper()
	pkKey, pkCert := certtest.MkSelfSignedCert(t)
	kekKey, kekCert := certtest.MkSelfSignedCert(t)
	dbKey, dbCert := certtest.MkSelfSignedCert(t)
	return &testKeys{pkKey, pkCert, kekKey, kekCert, dbKey, dbCert}
}

// newStore creates a store with PK and KEK enrolled.
func (k *testKeys) newStore(t *testing.T) *AuthVariableStore {
	t.Helper()
	return NewAuthVariableStore(
		mkTestDatabase(t, k.pkCert),
		mkTestDatabase(t, k.kekCert),
		mkTestDatabase(t),
		mkTestDatabase(t),
	)
}

// signUpdate creates a signed EFI_VARIABLE_AUTHENTICATION2 update package
// replacing the variable v with content.
func signUpdate(t *testing.T, v efivar.Efivar, content *SignatureDatabase, key crypto.Signer, cert *x509.Certificate, ts *util.EFITime, opts ...pkcs7.Option) []byte {
	t.Helper()
	_, m, err := SignEFIVariableWithOptions(v, content, key, cert, ts, opts...)
	if err != nil {
		t.Fatalf("failed signing variable update: %v", err)
	}
	return m.Bytes()
}

func efiTime(year uint16, month uint8) *util.EFITime {
	return &util.EFITime{Year: year, Month: month, Day: 1, TimeZone: int16(util.EFI_UNSPECIFIED_TIMEZONE)}
}

func TestAuthorizationHierarchy(t *testing.T) {
	keys := mkTestKeys(t)

	tests := []struct {
		name    string
		v       efivar.Efivar
		key     crypto.Signer
		cert    *x509.Certificate
		wantErr error
	}{
		{"PK updates itself", efivar.PK, keys.pkKey, keys.pkCert, nil},
		{"KEK can not update PK", efivar.PK, keys.kekKey, keys.kekCert, ErrSignerNotAuthorized},
		{"db can not update PK", efivar.PK, keys.dbKey, keys.dbCert, ErrSignerNotAuthorized},
		{"PK updates KEK", efivar.KEK, keys.pkKey, keys.pkCert, nil},
		{"KEK can not update itself", efivar.KEK, keys.kekKey, keys.kekCert, ErrSignerNotAuthorized},
		{"db can not update KEK", efivar.KEK, keys.dbKey, keys.dbCert, ErrSignerNotAuthorized},
		{"PK updates db", efivar.Db, keys.pkKey, keys.pkCert, nil},
		{"KEK updates db", efivar.Db, keys.kekKey, keys.kekCert, nil},
		{"db can not update itself", efivar.Db, keys.dbKey, keys.dbCert, ErrSignerNotAuthorized},
		{"PK updates dbx", efivar.Dbx, keys.pkKey, keys.pkCert, nil},
		{"KEK updates dbx", efivar.Dbx, keys.kekKey, keys.kekCert, nil},
		{"db can not update dbx", efivar.Dbx, keys.dbKey, keys.dbCert, ErrSignerNotAuthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := keys.newStore(t)
			newdb := mkTestDatabase(t, keys.dbCert)
			payload := signUpdate(t, tt.v, newdb, tt.key, tt.cert, efiTime(2024, 1))

			_, err := store.VerifyUpdate(tt.v, payload)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("got error %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyUpdateYieldsCanonicalState(t *testing.T) {
	keys := mkTestKeys(t)
	store := keys.newStore(t)

	newdb := mkTestDatabase(t, keys.dbCert)
	payload := signUpdate(t, efivar.Db, newdb, keys.kekKey, keys.kekCert, efiTime(2024, 1))

	update, err := store.VerifyUpdate(efivar.Db, payload)
	if err != nil {
		t.Fatalf("failed verifying update: %v", err)
	}

	// The canonical state must serialize and parse back identically.
	parsed, err := ReadSignatureDatabase(bytes.NewReader(update.Bytes()))
	if err != nil {
		t.Fatalf("canonical state does not parse: %v", err)
	}
	if !bytes.Equal(parsed.Bytes(), update.Bytes()) {
		t.Fatal("canonical state does not round-trip")
	}
	if !update.Database.SigDataExists(CERT_X509_GUID, &SignatureData{Owner: *testOwnerGUID, Data: keys.dbCert.Raw}) {
		t.Fatal("canonical state does not contain the enrolled certificate")
	}

	// VerifyUpdate must not mutate the store.
	current, _ := store.Database("db")
	if len(*current) != 0 {
		t.Fatal("VerifyUpdate mutated the store")
	}
}

func TestApplyUpdateCommitsState(t *testing.T) {
	keys := mkTestKeys(t)
	store := keys.newStore(t)

	newdb := mkTestDatabase(t, keys.dbCert)
	payload := signUpdate(t, efivar.Db, newdb, keys.kekKey, keys.kekCert, efiTime(2024, 1))

	db, err := store.ApplyUpdate(efivar.Db, payload)
	if err != nil {
		t.Fatalf("failed applying update: %v", err)
	}
	if !db.SigDataExists(CERT_X509_GUID, &SignatureData{Owner: *testOwnerGUID, Data: keys.dbCert.Raw}) {
		t.Fatal("store does not contain the enrolled certificate")
	}

	// A PK rotation is authorized by the old PK and replaces the trust anchor.
	newPkKey, newPkCert := certtest.MkSelfSignedCert(t)
	pkdb := mkTestDatabase(t, newPkCert)
	payload = signUpdate(t, efivar.PK, pkdb, keys.pkKey, keys.pkCert, efiTime(2024, 2))
	if _, err := store.ApplyUpdate(efivar.PK, payload); err != nil {
		t.Fatalf("failed rotating PK: %v", err)
	}

	// After the rotation the old PK is no longer authorized, the new PK is.
	kekdb := mkTestDatabase(t, keys.kekCert)
	payload = signUpdate(t, efivar.KEK, kekdb, keys.pkKey, keys.pkCert, efiTime(2024, 3))
	if _, err := store.VerifyUpdate(efivar.KEK, payload); !errors.Is(err, ErrSignerNotAuthorized) {
		t.Fatalf("old PK should not be authorized after rotation, got %v", err)
	}
	payload = signUpdate(t, efivar.KEK, kekdb, newPkKey, newPkCert, efiTime(2024, 3))
	if _, err := store.VerifyUpdate(efivar.KEK, payload); err != nil {
		t.Fatalf("new PK should be authorized after rotation, got %v", err)
	}
}

func TestTimestampRollback(t *testing.T) {
	keys := mkTestKeys(t)
	store := keys.newStore(t)
	newdb := mkTestDatabase(t, keys.dbCert)

	first := signUpdate(t, efivar.Db, newdb, keys.kekKey, keys.kekCert, efiTime(2024, 6))
	if _, err := store.ApplyUpdate(efivar.Db, first); err != nil {
		t.Fatalf("failed applying first update: %v", err)
	}

	// Replaying the same update must fail: the timestamp is not newer.
	if _, err := store.ApplyUpdate(efivar.Db, first); !errors.Is(err, ErrTimestampRollback) {
		t.Fatalf("replayed update should be rejected, got %v", err)
	}

	// An older timestamp must be rejected.
	older := signUpdate(t, efivar.Db, newdb, keys.kekKey, keys.kekCert, efiTime(2024, 1))
	if _, err := store.ApplyUpdate(efivar.Db, older); !errors.Is(err, ErrTimestampRollback) {
		t.Fatalf("older update should be rejected, got %v", err)
	}

	// A newer timestamp is accepted.
	newer := signUpdate(t, efivar.Db, newdb, keys.kekKey, keys.kekCert, efiTime(2024, 7))
	if _, err := store.ApplyUpdate(efivar.Db, newer); err != nil {
		t.Fatalf("newer update should be accepted, got %v", err)
	}
}

func TestSeededTimestamp(t *testing.T) {
	keys := mkTestKeys(t)
	store := keys.newStore(t)
	store.SetTimestamp("db", *efiTime(2024, 6))

	newdb := mkTestDatabase(t, keys.dbCert)
	payload := signUpdate(t, efivar.Db, newdb, keys.kekKey, keys.kekCert, efiTime(2024, 1))
	if _, err := store.VerifyUpdate(efivar.Db, payload); !errors.Is(err, ErrTimestampRollback) {
		t.Fatalf("update older than the seeded timestamp should be rejected, got %v", err)
	}
}

func TestTamperedAuthenticationData(t *testing.T) {
	keys := mkTestKeys(t)
	newdb := mkTestDatabase(t, keys.dbCert)
	ts := efiTime(2024, 1)
	payload := signUpdate(t, efivar.Db, newdb, keys.kekKey, keys.kekCert, ts)

	// Flip a byte in the timestamp of the authentication descriptor.
	t.Run("timestamp", func(t *testing.T) {
		store := keys.newStore(t)
		tampered := bytes.Clone(payload)
		tampered[1] ^= 0xff
		if _, err := store.VerifyUpdate(efivar.Db, tampered); err == nil {
			t.Fatal("tampered timestamp should be rejected")
		}
	})

	// Flip a byte in the variable content after the authentication descriptor.
	t.Run("content", func(t *testing.T) {
		store := keys.newStore(t)
		tampered := bytes.Clone(payload)
		tampered[len(tampered)-1] ^= 0xff
		if _, err := store.VerifyUpdate(efivar.Db, tampered); err == nil {
			t.Fatal("tampered content should be rejected")
		}
	})

	// Flip a byte of the authenticated message digest inside the PKCS7. The
	// signature is computed over the DER encoding of the authenticated
	// attributes, so any re-encoding or reordering of the authentication data
	// invalidates it.
	t.Run("authenticated digest", func(t *testing.T) {
		store := keys.newStore(t)
		tampered := bytes.Clone(payload)
		digest := crypto.SHA256.New()
		digest.Write(SignedContent(efivar.Db, *ts, newdb.Bytes()))
		offset := bytes.Index(tampered, digest.Sum(nil))
		if offset == -1 {
			t.Fatal("could not locate authenticated digest in payload")
		}
		tampered[offset] ^= 0xff
		if _, err := store.VerifyUpdate(efivar.Db, tampered); err == nil {
			t.Fatal("tampered authenticated digest should be rejected")
		}
	})

	// Verifying against different variable attributes changes the signed
	// content and must fail.
	t.Run("attributes", func(t *testing.T) {
		store := keys.newStore(t)
		v := efivar.Db
		v.Attributes &^= attributes.EFI_VARIABLE_NON_VOLATILE
		if _, err := store.VerifyUpdate(v, payload); err == nil {
			t.Fatal("mismatched attributes should be rejected")
		}
	})

	// Truncating the signature must be a parse error, not a bypass.
	t.Run("truncated", func(t *testing.T) {
		store := keys.newStore(t)
		if _, err := store.VerifyUpdate(efivar.Db, payload[:len(payload)/2]); err == nil {
			t.Fatal("truncated payload should be rejected")
		}
	})
}

func TestVariableAttributeChecks(t *testing.T) {
	keys := mkTestKeys(t)
	newdb := mkTestDatabase(t, keys.dbCert)

	// A variable without the time-based authenticated write access attribute
	// can not take an authenticated update.
	v := efivar.Efivar{
		Name: "db",
		GUID: util.StringToGUID("d719b2cb-3d3a-4596-a3bc-dad00e67656f"),
		Attributes: attributes.EFI_VARIABLE_NON_VOLATILE |
			attributes.EFI_VARIABLE_BOOTSERVICE_ACCESS |
			attributes.EFI_VARIABLE_RUNTIME_ACCESS,
	}
	payload := signUpdate(t, v, newdb, keys.kekKey, keys.kekCert, efiTime(2024, 1))
	store := keys.newStore(t)
	if _, err := store.VerifyUpdate(v, payload); !errors.Is(err, ErrMissingAuthAttribute) {
		t.Fatalf("variable without authenticated write access should be rejected, got %v", err)
	}

	// Unknown variables are rejected.
	v = efivar.Efivar{
		Name:       "NotASecureBootVariable",
		GUID:       util.StringToGUID("d719b2cb-3d3a-4596-a3bc-dad00e67656f"),
		Attributes: efivar.Db.Attributes,
	}
	payload = signUpdate(t, v, newdb, keys.kekKey, keys.kekCert, efiTime(2024, 1))
	if _, err := store.VerifyUpdate(v, payload); !errors.Is(err, ErrUnknownAuthVariable) {
		t.Fatalf("unknown variable should be rejected, got %v", err)
	}
}

func TestNoAuthorizedKeys(t *testing.T) {
	keys := mkTestKeys(t)
	// No PK enrolled: nothing can authorize a KEK update.
	store := NewAuthVariableStore(nil, nil, nil, nil)
	kekdb := mkTestDatabase(t, keys.kekCert)
	payload := signUpdate(t, efivar.KEK, kekdb, keys.pkKey, keys.pkCert, efiTime(2024, 1))
	if _, err := store.VerifyUpdate(efivar.KEK, payload); !errors.Is(err, ErrNoAuthorizedKeys) {
		t.Fatalf("update without enrolled authorizing keys should be rejected, got %v", err)
	}
}

func TestChainedSigner(t *testing.T) {
	keys := mkTestKeys(t)
	leafKey, leafCert, chain := certtest.MkCertChain(t)
	root := chain[len(chain)-1]

	// Enroll the root of the chain in KEK.
	store := NewAuthVariableStore(
		mkTestDatabase(t, keys.pkCert),
		mkTestDatabase(t, root),
		mkTestDatabase(t),
		mkTestDatabase(t),
	)

	newdb := mkTestDatabase(t, keys.dbCert)
	payload := signUpdate(t, efivar.Db, newdb, leafKey, leafCert, efiTime(2024, 1),
		pkcs7.WithAdditionalCerts(chain))

	update, err := store.VerifyUpdate(efivar.Db, payload)
	if err != nil {
		t.Fatalf("chained signer should be authorized, got %v", err)
	}
	if !update.Signer.Equal(leafCert) {
		t.Fatal("unexpected signer certificate")
	}

	// The same signature is not authorized when the root is not enrolled.
	store = NewAuthVariableStore(
		mkTestDatabase(t, keys.pkCert),
		mkTestDatabase(t, keys.kekCert),
		mkTestDatabase(t),
		mkTestDatabase(t),
	)
	if _, err := store.VerifyUpdate(efivar.Db, payload); !errors.Is(err, ErrSignerNotAuthorized) {
		t.Fatalf("unenrolled chain root should be rejected, got %v", err)
	}
}

func TestAppendUpdate(t *testing.T) {
	keys := mkTestKeys(t)
	store := keys.newStore(t)

	// Enroll the first certificate with a replace update.
	first := mkTestDatabase(t, keys.dbCert)
	payload := signUpdate(t, efivar.Db, first, keys.kekKey, keys.kekCert, efiTime(2024, 1))
	if _, err := store.ApplyUpdate(efivar.Db, payload); err != nil {
		t.Fatalf("failed applying first update: %v", err)
	}

	// Append a second certificate.
	appendVar := efivar.Db
	appendVar.Attributes |= attributes.EFI_VARIABLE_APPEND_WRITE
	_, secondCert := certtest.MkSelfSignedCert(t)
	second := mkTestDatabase(t, secondCert)
	payload = signUpdate(t, appendVar, second, keys.kekKey, keys.kekCert, efiTime(2024, 2))
	db, err := store.ApplyUpdate(appendVar, payload)
	if err != nil {
		t.Fatalf("failed applying append update: %v", err)
	}

	for _, cert := range []*x509.Certificate{keys.dbCert, secondCert} {
		if !db.SigDataExists(CERT_X509_GUID, &SignatureData{Owner: *testOwnerGUID, Data: cert.Raw}) {
			t.Fatal("appended database is missing a certificate")
		}
	}
}

func TestExpiredSigningTimeStillVerifies(t *testing.T) {
	// The timestamp of the authentication descriptor is not wall-clock
	// validated against the certificate lifetime; the hierarchy and the
	// signature decide. This ensures offline verification of old, legitimate
	// update packages keeps working.
	keys := mkTestKeys(t)
	store := keys.newStore(t)
	newdb := mkTestDatabase(t, keys.dbCert)
	old := &util.EFITime{Year: 2020, Month: 1, Day: 1}
	payload := signUpdate(t, efivar.Db, newdb, keys.kekKey, keys.kekCert, old)
	if _, err := store.VerifyUpdate(efivar.Db, payload); err != nil {
		t.Fatalf("old but valid update should verify, got %v", err)
	}
}
