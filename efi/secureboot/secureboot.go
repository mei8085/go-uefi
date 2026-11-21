// Package secureboot implements offline UEFI Secure Boot image admission.
//
// It answers a single question: given the contents of the db (authorized) and
// dbx (forbidden) signature databases, is an EFI image allowed to execute?
//
// The decision follows the UEFI specification (EFI_IMAGE_SECURITY_DATABASE /
// DxeImageVerificationHandler):
//
//   - A SHA-256 image hash present in dbx denies the image.
//   - A SHA-256 image hash present in db authorizes the image.
//   - Otherwise each Authenticode signature is evaluated:
//   - a signature whose certificate chain contains a certificate present in
//     dbx is revoked and can never authorize the image;
//   - a signature that cryptographically validates and chains to a certificate
//     present in db authorizes the image.
//
// Revocation always takes precedence: a revoked hash or certificate denies the
// image even if a database entry elsewhere would authorize it.
//
// The verdict depends only on the logical contents of db and dbx, never on the
// order of signature lists, the order of entries within a list, or the way
// entries are grouped into encoded EFI_SIGNATURE_LIST structures.
package secureboot

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"io"

	"github.com/foxboron/go-uefi/authenticode"
	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/go-uefi/efi/util"
)

var (
	// ErrNoSignatures is returned when the image carries no Authenticode
	// signatures. An unsigned image cannot be admitted under Secure Boot.
	ErrNoSignatures = errors.New("image has no signatures")

	// ErrImageHashDenied is returned when the image hash is present in dbx.
	ErrImageHashDenied = errors.New("image hash is present in the forbidden signature database (dbx)")

	// ErrCertRevoked is returned when every valid signature chains through a
	// certificate present in dbx.
	ErrCertRevoked = errors.New("signature chain contains a certificate present in the forbidden signature database (dbx)")

	// ErrNoAuthorizedSignature is returned when none of the image's signatures
	// chain to a certificate present in db, and no db hash matches.
	ErrNoAuthorizedSignature = errors.New("no signature authorized by the allowed signature database (db)")
)

// VerifyImage evaluates an already parsed PE/COFF image against a Secure Boot
// policy.
//
// It returns true only when the image is admitted: either its SHA-256 hash is
// present in db, or at least one Authenticode signature cryptographically
// validates and chains to a certificate in db without any certificate of the
// chain being present in dbx. Any other outcome (unsigned image, revoked hash,
// revoked certificate, or no trusted chain) returns false with a sentinel
// error describing the reason.
//
// The result is independent of the encoding and entry ordering of db and dbx.
func VerifyImage(binary *authenticode.PECOFFBinary, db, dbx *signature.SignatureDatabase) (bool, error) {
	db = ensureDatabase(db)
	dbx = ensureDatabase(dbx)

	imageHash := binary.Hash(crypto.SHA256)

	// Forbidden hashes are checked before anything else. A revoked hash denies
	// the image regardless of any signature or db entry.
	if hashPresent(dbx, imageHash) {
		return false, ErrImageHashDenied
	}

	// An explicit hash authorization in db admits the image without needing a
	// valid signature.
	if hashPresent(db, imageHash) {
		return true, nil
	}

	sigs, err := binary.VerifyAuthenticode()
	if err != nil {
		if errors.Is(err, authenticode.ErrNoSignatures) {
			return false, ErrNoSignatures
		}
		return false, err
	}
	if len(sigs) == 0 {
		return false, ErrNoAuthorizedSignature
	}

	revoked := false
	for _, sig := range sigs {
		// The SignerInfo identifies the exact certificate that produced this
		// signature. Start chain construction from it rather than assuming the
		// embedded certificates are ordered leaf-first.
		leaves := sig.Pkcs.SignerCertificates()
		if len(leaves) == 0 {
			continue
		}
		certs := sig.Pkcs.Certs

		// A single revoked certificate anywhere in the chain invalidates this
		// signature. Revocation wins over authorization for this signature.
		if anyCertInDatabase(dbx, certs) {
			revoked = true
			continue
		}

		// The embedded certificates must form a valid signature chain that
		// terminates at a certificate trusted by db.
		if chainToTrustedCert(leaves[0], certs, db) {
			return true, nil
		}
	}

	if revoked {
		return false, ErrCertRevoked
	}
	return false, ErrNoAuthorizedSignature
}

// VerifyImageReader parses a PE/COFF image from r and evaluates it against the
// supplied Secure Boot databases. It is a convenience wrapper around Parse and
// VerifyImage.
func VerifyImageReader(r io.ReaderAt, db, dbx *signature.SignatureDatabase) (bool, error) {
	binary, err := authenticode.Parse(r)
	if err != nil {
		return false, err
	}
	return VerifyImage(binary, db, dbx)
}

// ensureDatabase treats a nil database as an empty one so lookups never
// dereference a nil pointer.
func ensureDatabase(sd *signature.SignatureDatabase) *signature.SignatureDatabase {
	if sd == nil {
		return signature.NewSignatureDatabase()
	}
	return sd
}

// hashPresent reports whether a raw hash is present in a SHA-256 signature
// database. It compares hash bytes only; the EFI Signature Owner is not part of
// the security decision and is therefore ignored.
func hashPresent(sd *signature.SignatureDatabase, hash []byte) bool {
	for _, list := range *sd {
		if !util.CmpEFIGUID(list.SignatureType, signature.CERT_SHA256_GUID) {
			continue
		}
		for _, sig := range list.Signatures {
			if bytes.Equal(sig.Data, hash) {
				return true
			}
		}
	}
	return false
}

// anyCertInDatabase reports whether any of the certificates is present in an
// X509 signature database. Matching is done on the raw DER encoding, exactly as
// stored in the database, which makes the comparison independent of any
// re-encoding.
func anyCertInDatabase(sd *signature.SignatureDatabase, certs []*x509.Certificate) bool {
	for _, list := range *sd {
		if !util.CmpEFIGUID(list.SignatureType, signature.CERT_X509_GUID) {
			continue
		}
		for _, sig := range list.Signatures {
			for _, cert := range certs {
				if bytes.Equal(sig.Data, cert.Raw) {
					return true
				}
			}
		}
	}
	return false
}

// chainToTrustedCert reports whether the embedded certificates form a valid
// signature chain from leaf that terminates at a certificate present in db.
//
// The leaf certificate (which produced the signature) is the starting point and
// each link must be signed by the next certificate until a certificate trusted
// by db is reached. Only embedded certificates are considered: Secure Boot
// trusts exactly what the databases authorize and has no external root store.
func chainToTrustedCert(leaf *x509.Certificate, certs []*x509.Certificate, db *signature.SignatureDatabase) bool {
	// A leaf may itself be directly trusted by db.
	if certInDatabase(db, leaf) {
		return true
	}

	current := leaf
	visited := map[string]bool{}

	for {
		key := string(current.Raw)
		if visited[key] {
			// A cycle can never reach a trusted root.
			return false
		}
		visited[key] = true

		issuer := findIssuer(certs, current)
		if issuer == nil {
			// No embedded certificate can continue the chain.
			return false
		}

		// Every link of the chain must be a genuine certificate signature.
		if err := current.CheckSignatureFrom(issuer); err != nil {
			return false
		}

		if certInDatabase(db, issuer) {
			return true
		}
		current = issuer
	}
}

// findIssuer returns the embedded certificate whose subject matches cert's
// issuer, or nil when none does.
func findIssuer(certs []*x509.Certificate, cert *x509.Certificate) *x509.Certificate {
	for _, candidate := range certs {
		if bytes.Equal(candidate.RawSubject, cert.RawIssuer) {
			return candidate
		}
	}
	return nil
}

// certInDatabase reports whether a single certificate is present in an X509
// signature database by comparing raw DER bytes.
func certInDatabase(sd *signature.SignatureDatabase, cert *x509.Certificate) bool {
	for _, list := range *sd {
		if !util.CmpEFIGUID(list.SignatureType, signature.CERT_X509_GUID) {
			continue
		}
		for _, sig := range list.Signatures {
			if bytes.Equal(sig.Data, cert.Raw) {
				return true
			}
		}
	}
	return false
}
