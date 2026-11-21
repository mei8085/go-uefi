package signature

import (
	"bytes"
	"crypto/x509"

	"github.com/pkg/errors"

	"github.com/foxboron/go-uefi/efi/attributes"
	"github.com/foxboron/go-uefi/efi/util"
	"github.com/foxboron/go-uefi/efivar"
	"github.com/foxboron/go-uefi/pkcs7"
)

// Offline verification of authenticated secure boot variable updates.
//
// The UEFI specification (section 8.2.2, "Secure Boot Variable Updates")
// defines an authorization hierarchy between the secure boot key databases:
//
//	PK   -> authorized by the currently enrolled PK (self-authorization)
//	KEK  -> authorized by the PK
//	db   -> authorized by the PK or any key in KEK
//	dbx  -> authorized by the PK or any key in KEK
//
// AuthVariableStore implements this hierarchy for offline verification of
// EFI_VARIABLE_AUTHENTICATION2 update packages. Every update is authorized
// from the permissions of the signer and the attributes of the variable:
//
//   - The variable must carry EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS.
//   - The timestamp of the update must be strictly newer than the timestamp
//     of the previously accepted update for the variable (anti-rollback).
//   - The PKCS7 signature must validate against the canonical signed content
//     (VariableName || VendorGuid || Attributes || Time || Data). A mismatch
//     of the signed digest, or any reordering/re-encoding of the
//     authenticated data, rejects the update.
//   - The signing certificate must chain up to a certificate enrolled in the
//     key database(s) authorized for the variable.
//
// A successfully verified update yields the canonical variable state which
// can be written to the variable store.

var (
	ErrUnknownAuthVariable  = errors.New("not a known secure boot authenticated variable")
	ErrMissingAuthAttribute = errors.New("variable is missing EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS")
	ErrTimestampRollback    = errors.New("timestamp of update is not newer than the timestamp of the current variable")
	ErrNoAuthorizedKeys     = errors.New("no enrolled keys can authorize an update of the variable")
	ErrSignerNotAuthorized  = errors.New("signer is not authorized to update the variable")
	ErrInvalidSignature     = errors.New("invalid signature over the variable update")
)

// secureBootVariableHierarchy maps a secure boot variable to the names of
// the key databases whose enrolled certificates authorize updates to it.
var secureBootVariableHierarchy = map[string][]string{
	"PK":  {"PK"},
	"KEK": {"PK"},
	"db":  {"PK", "KEK"},
	"dbx": {"PK", "KEK"},
}

// VerifiedUpdate is the result of a successfully verified authenticated
// variable update.
type VerifiedUpdate struct {
	// Variable the update applies to.
	Variable efivar.Efivar
	// Database is the canonical new state of the variable.
	Database *SignatureDatabase
	// Timestamp of the accepted authentication descriptor.
	Timestamp util.EFITime
	// Signer is the certificate that authorized the update.
	Signer *x509.Certificate
}

// Bytes returns the canonical serialized state of the updated variable,
// suitable for writing to the variable store.
func (u *VerifiedUpdate) Bytes() []byte {
	return u.Database.Bytes()
}

// AuthVariableStore keeps the current state of the secure boot key
// databases for offline verification of authenticated variable updates.
type AuthVariableStore struct {
	databases  map[string]*SignatureDatabase
	timestamps map[string]util.EFITime
}

// NewAuthVariableStore creates a store from the currently enrolled key
// databases. A nil database is treated as not enrolled.
func NewAuthVariableStore(pk, kek, db, dbx *SignatureDatabase) *AuthVariableStore {
	return &AuthVariableStore{
		databases: map[string]*SignatureDatabase{
			"PK":  pk,
			"KEK": kek,
			"db":  db,
			"dbx": dbx,
		},
		timestamps: map[string]util.EFITime{},
	}
}

// Database returns the current state of the named variable.
func (s *AuthVariableStore) Database(name string) (*SignatureDatabase, bool) {
	db, ok := s.databases[name]
	return db, ok
}

// SetTimestamp seeds the timestamp of the last accepted update for a
// variable. This should reflect the timestamp of the authentication
// descriptor the currently enrolled variable was written with, and protects
// against replaying older update packages.
func (s *AuthVariableStore) SetTimestamp(name string, t util.EFITime) {
	s.timestamps[name] = t
}

// x509Certificates extracts the X.509 certificates enrolled in a signature
// database. Non-certificate entries (hashes, external management) can not
// authorize updates and are skipped.
func x509Certificates(db *SignatureDatabase) []*x509.Certificate {
	var certs []*x509.Certificate
	if db == nil {
		return nil
	}
	for _, l := range *db {
		if !util.CmpEFIGUID(l.SignatureType, CERT_X509_GUID) {
			continue
		}
		for _, sig := range l.Signatures {
			cert, err := x509.ParseCertificate(sig.Data)
			if err != nil {
				continue
			}
			certs = append(certs, cert)
		}
	}
	return certs
}

// authorizedCertificates returns the certificates that are allowed to
// authorize an update of the named variable according to the secure boot
// key hierarchy.
func (s *AuthVariableStore) authorizedCertificates(name string) []*x509.Certificate {
	var certs []*x509.Certificate
	for _, dbname := range secureBootVariableHierarchy[name] {
		db, ok := s.databases[dbname]
		if !ok {
			continue
		}
		certs = append(certs, x509Certificates(db)...)
	}
	return certs
}

// isEnrolled returns true if cert is byte-identical to one of the enrolled
// certificates. An enrolled certificate is a trust anchor and is trusted by
// fiat, regardless of its validity period.
func isEnrolled(cert *x509.Certificate, enrolled []*x509.Certificate) bool {
	for _, c := range enrolled {
		if cert.Equal(c) {
			return true
		}
	}
	return false
}

// VerifyUpdate verifies an EFI_VARIABLE_AUTHENTICATION2 update package for
// the variable v against the current state of the key databases, without
// modifying the store. It returns the verified update on success.
func (s *AuthVariableStore) VerifyUpdate(v efivar.Efivar, payload []byte) (*VerifiedUpdate, error) {
	if _, ok := secureBootVariableHierarchy[v.Name]; !ok {
		return nil, errors.Wrapf(ErrUnknownAuthVariable, "variable %q", v.Name)
	}

	// Only variables with time-based authenticated write access can be
	// updated with an EFI_VARIABLE_AUTHENTICATION2 descriptor.
	if v.Attributes&attributes.EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS == 0 {
		return nil, errors.Wrapf(ErrMissingAuthAttribute, "variable %q", v.Name)
	}

	buf := bytes.NewBuffer(payload)
	auth, err := ReadEFIVariableAuthencation2(buf)
	if err != nil {
		return nil, err
	}

	// The remainder of the payload is the new variable content covered by
	// the signature.
	data := buf.Bytes()

	// Anti-rollback: the timestamp of the update must be strictly newer
	// than the timestamp of the last accepted update.
	if last, ok := s.timestamps[v.Name]; ok {
		if !auth.Time.After(last) {
			return nil, errors.Wrapf(ErrTimestampRollback, "variable %q update timestamp %s is not newer than %s",
				v.Name, auth.Time.Format(), last.Format())
		}
	}

	// Reconstruct the canonical signed content. Any reordering or
	// re-encoding of the authenticated data changes these bytes and
	// invalidates the signature below.
	content := SignedContent(v, auth.Time, data)

	sig, err := pkcs7.ParsePKCS7(auth.AuthInfo.CertData)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse PKCS7 signature")
	}

	authorized := s.authorizedCertificates(v.Name)
	if len(authorized) == 0 {
		return nil, errors.Wrapf(ErrNoAuthorizedKeys, "variable %q", v.Name)
	}

	roots := x509.NewCertPool()
	for _, cert := range authorized {
		roots.AddCert(cert)
	}

	signers := sig.SignerCertificates()
	if len(signers) == 0 {
		return nil, errors.Wrap(ErrInvalidSignature, "no signer certificate embedded in the signature")
	}

	authorizedSigner := false
	for _, signer := range signers {
		// The signer certificate must be enrolled in a key database
		// authorized for this variable, or chain up to an enrolled
		// certificate. Enrolled certificates are trust anchors and are
		// accepted by fiat; delegated chains are validated with any
		// additional certificates embedded in the signature as
		// intermediates.
		if !isEnrolled(signer, authorized) {
			intermediates := x509.NewCertPool()
			for _, cert := range sig.Certs {
				if cert.Equal(signer) {
					continue
				}
				intermediates.AddCert(cert)
			}
			if _, err := signer.Verify(x509.VerifyOptions{
				Roots:         roots,
				Intermediates: intermediates,
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			}); err != nil {
				continue
			}
		}
		authorizedSigner = true

		// The signature must validate over the canonical signed content,
		// including the authenticated message digest.
		ok, err := sig.VerifyContent(signer, content)
		if err != nil {
			return nil, errors.Wrapf(ErrInvalidSignature, "%v", err)
		}
		if !ok {
			continue
		}

		// The new variable content must be a well-formed signature
		// database so the update yields a canonical state that can be
		// written back to the variable store.
		db, err := ReadSignatureDatabase(bytes.NewReader(data))
		if err != nil {
			return nil, errors.Wrap(err, "update payload is not a well-formed signature database")
		}

		return &VerifiedUpdate{
			Variable:  v,
			Database:  &db,
			Timestamp: auth.Time,
			Signer:    signer,
		}, nil
	}

	if authorizedSigner {
		return nil, errors.Wrap(ErrInvalidSignature, "signature does not validate over the variable update")
	}
	return nil, errors.Wrapf(ErrSignerNotAuthorized, "variable %q", v.Name)
}

// ApplyUpdate verifies an authenticated variable update like VerifyUpdate
// and commits the resulting canonical state to the store. If the variable
// attributes include EFI_VARIABLE_APPEND_WRITE the update is merged into
// the current database instead of replacing it.
func (s *AuthVariableStore) ApplyUpdate(v efivar.Efivar, payload []byte) (*SignatureDatabase, error) {
	update, err := s.VerifyUpdate(v, payload)
	if err != nil {
		return nil, err
	}

	newdb := update.Database
	if v.Attributes&attributes.EFI_VARIABLE_APPEND_WRITE != 0 {
		if current, ok := s.databases[v.Name]; ok && current != nil {
			merged := *current
			merged.AppendDatabase(newdb)
			newdb = &merged
		}
	}

	s.databases[v.Name] = newdb
	s.timestamps[v.Name] = update.Timestamp
	return newdb, nil
}
