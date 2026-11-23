package signature

import (
	"bytes"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"reflect"
	"sort"
	"testing"

	"github.com/foxboron/go-uefi/efi/util"
)

// The tests in this file pin down the contract between reading, writing and
// editing a signature database. Every signature type known to the UEFI
// specification must round-trip, the size boundaries of each type must be
// enforced identically on all paths, and edited databases must stay valid.

var consistencyOwner = util.EFIGUID{Data1: 0xc1095e1b, Data2: 0x8a3b, Data3: 0x4cf5, Data4: [8]uint8{0x9d, 0x4a, 0xaf, 0xc7, 0xd7, 0x5d, 0xca, 0x68}}

// payload returns a deterministic payload of the requested length.
func payload(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i%251) + 1
	}
	return b
}

// fixedSignatureTypes lists every specification type with a fixed entry size
// together with the payload size that produces a valid entry.
func fixedSignatureTypes() []struct {
	name   string
	guid   util.EFIGUID
	length int // signature payload length, signature owner not included
} {
	return []struct {
		name   string
		guid   util.EFIGUID
		length int
	}{
		{"SHA1", CERT_SHA1_GUID, 20},
		{"SHA224", CERT_SHA224_GUID, 28},
		{"SHA256", CERT_SHA256_GUID, 32},
		{"SHA384", CERT_SHA384_GUID, 48},
		{"SHA512", CERT_SHA512_GUID, 64},
		{"SM3", CERT_SM3_GUID, 32},
		{"RSA2048", CERT_RSA2048_GUID, 256},
		{"RSA2048 SHA1", CERT_RSA2048_SHA1_GUID, 256},
		{"RSA2048 SHA256", CERT_RSA2048_SHA256_GUID, 256},
		{"X509 SHA256", CERT_X509_SHA256_GUID, 48},
		{"X509 SHA384", CERT_X509_SHA384_GUID, 64},
		{"X509 SHA512", CERT_X509_SHA512_GUID, 80},
		{"X509 SM3", CERT_X509_SM3_GUID, 48},
		{"EXTERNAL MANAGEMENT", CERT_EXTERNAL_MANAGEMENT_GUID, 1},
	}
}

// TestAllSignatureTypesRoundTrip appends, serializes, re-reads and removes an
// entry for every signature type the specification defines.
func TestAllSignatureTypesRoundTrip(t *testing.T) {
	for _, tc := range fixedSignatureTypes() {
		t.Run(tc.name, func(t *testing.T) {
			data := payload(tc.length)
			wantSize := util.SizeofEFIGUID + uint32(tc.length)

			sl := NewSignatureList(tc.guid)
			if err := sl.AppendBytes(consistencyOwner, data); err != nil {
				t.Fatalf("append %s: %v", tc.name, err)
			}
			if sl.Size != wantSize {
				t.Fatalf("size: got %d want %d", sl.Size, wantSize)
			}
			if sl.ListSize != SizeofSignatureList+wantSize {
				t.Fatalf("list size: got %d want %d", sl.ListSize, SizeofSignatureList+wantSize)
			}
			if err := sl.Validate(); err != nil {
				t.Fatalf("validate after append: %v", err)
			}

			encoded := sl.Bytes()
			got, err := ReadSignatureList(bytes.NewReader(encoded))
			if err != nil {
				t.Fatalf("read back: %v", err)
			}
			if !util.CmpEFIGUID(got.SignatureType, tc.guid) {
				t.Fatalf("signature type changed: %s", got.SignatureType.Format())
			}
			if got.Size != wantSize || got.ListSize != sl.ListSize {
				t.Fatalf("re-read sizes: size %d list %d", got.Size, got.ListSize)
			}
			if len(got.Signatures) != 1 {
				t.Fatalf("re-read signatures: got %d", len(got.Signatures))
			}
			if !bytes.Equal(got.Signatures[0].Data, data) {
				t.Fatalf("payload changed on round trip")
			}
			if !bytes.Equal(got.Bytes(), encoded) {
				t.Fatalf("re-encoding is not byte identical")
			}

			if err := got.RemoveSignature(SignatureData{Owner: consistencyOwner, Data: data}); err != nil {
				t.Fatalf("remove: %v", err)
			}
			if len(got.Signatures) != 0 {
				t.Fatalf("remove: %d signatures left", len(got.Signatures))
			}
			if got.ListSize != SizeofSignatureList || got.Size != 0 {
				t.Fatalf("remove: list not reset, size %d list %d", got.Size, got.ListSize)
			}
			if err := got.Validate(); err != nil {
				t.Fatalf("validate after remove: %v", err)
			}
		})
	}
}

// TestSignatureTypeLengthBoundaries checks that exactly the documented entry
// size is accepted and that one byte above and below is rejected on both the
// edit and write paths and on the read path.
func TestSignatureTypeLengthBoundaries(t *testing.T) {
	for _, tc := range fixedSignatureTypes() {
		t.Run(tc.name, func(t *testing.T) {
			for _, delta := range []int{-1, 1} {
				n := tc.length + delta
				if n < 0 {
					continue
				}
				sl := NewSignatureList(tc.guid)
				err := sl.AppendBytes(consistencyOwner, payload(n))
				if !errors.Is(err, ErrSigSizeMismatch) {
					t.Fatalf("append length %d: got %v, want ErrSigSizeMismatch", n, err)
				}
				if len(sl.Signatures) != 0 || sl.ListSize != SizeofSignatureList {
					t.Fatalf("append length %d: list mutated on rejected append", n)
				}

				// The same boundary must be enforced when the database picks a
				// signature list.
				db := NewSignatureDatabase()
				err = db.Append(tc.guid, consistencyOwner, payload(n))
				if !errors.Is(err, ErrSigSizeMismatch) {
					t.Fatalf("database append length %d: got %v, want ErrSigSizeMismatch", n, err)
				}
				if len(*db) != 0 {
					t.Fatalf("database append length %d: database mutated on rejected append", n)
				}
			}

			// A hand-built list with the wrong SignatureSize must be rejected
			// when read, even when the encoded length is self-consistent.
			listSize := SizeofSignatureList + (util.SizeofEFIGUID + uint32(tc.length) + 1)
			raw := encodeList(t, tc.guid, listSize, 0, util.SizeofEFIGUID+uint32(tc.length)+1, payload(tc.length+1))
			if _, err := ReadSignatureList(bytes.NewReader(raw)); !errors.Is(err, ErrSigSizeMismatch) {
				t.Fatalf("read wrong entry size: got %v, want ErrSigSizeMismatch", err)
			}
		})
	}
}

// TestMinimumSignatureEntrySize pins the smallest entry every type allows: an
// EFI_SIGNATURE_DATA is never smaller than its SignatureOwner GUID.
func TestMinimumSignatureEntrySize(t *testing.T) {
	for _, tc := range fixedSignatureTypes() {
		scheme, ok := LookupSignatureScheme(tc.guid)
		if !ok {
			t.Fatalf("%s: no scheme", tc.name)
		}
		if scheme.Size <= util.SizeofEFIGUID {
			t.Fatalf("%s: scheme size %d does not reserve the owner GUID", tc.name, scheme.Size)
		}
	}

	// X509 has a variable entry size; a zero length certificate is rejected
	// while a one byte certificate is the smallest value that fits.
	sl := NewSignatureList(CERT_X509_GUID)
	if err := sl.AppendBytes(consistencyOwner, nil); !errors.Is(err, ErrSigSizeMismatch) {
		t.Fatalf("x509 empty payload: got %v, want ErrSigSizeMismatch", err)
	}
	if err := sl.AppendBytes(consistencyOwner, payload(1)); err != nil {
		t.Fatalf("x509 one byte payload: %v", err)
	}
	if sl.Size != util.SizeofEFIGUID+1 {
		t.Fatalf("x509 size: got %d want %d", sl.Size, util.SizeofEFIGUID+1)
	}

	// A signature list carries one signature size. A different sized
	// certificate must not silently change the list invariant.
	if err := sl.AppendBytes(consistencyOwner, payload(2)); !errors.Is(err, ErrSigSizeMismatch) {
		t.Fatalf("x509 varying payload: got %v, want ErrSigSizeMismatch", err)
	}
	if err := sl.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

// TestX509PEMNormalization verifies that a PEM certificate is stored as DER
// and that both encodings address the same entry for exists and remove.
func TestX509PEMNormalization(t *testing.T) {
	der := payload(40)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	db := NewSignatureDatabase()
	if err := db.Append(CERT_X509_GUID, consistencyOwner, pemBytes); err != nil {
		t.Fatalf("append pem: %v", err)
	}
	if len(*db) != 1 || len((*db)[0].Signatures) != 1 {
		t.Fatalf("append pem: unexpected database shape")
	}
	stored := (*db)[0].Signatures[0].Data
	if !bytes.Equal(stored, der) {
		t.Fatalf("pem was not normalized to der")
	}
	if (*db)[0].Size != util.SizeofEFIGUID+uint32(len(der)) {
		t.Fatalf("pem entry keeps the pem length in the signature size")
	}
	if !db.BytesExists(CERT_X509_GUID, consistencyOwner, pemBytes) {
		t.Fatalf("pem exists check failed")
	}
	if !db.BytesExists(CERT_X509_GUID, consistencyOwner, der) {
		t.Fatalf("der exists check failed")
	}
	if err := db.Remove(CERT_X509_GUID, consistencyOwner, pemBytes); err != nil {
		t.Fatalf("remove pem: %v", err)
	}
	if !reflect.DeepEqual(*db, SignatureDatabase{}) {
		t.Fatalf("remove pem: database not empty")
	}
}

// TestReadSignatureListBoundaries covers the structural boundaries of an
// encoded EFI_SIGNATURE_LIST.
func TestReadSignatureListBoundaries(t *testing.T) {
	valid := func() []byte {
		sl := NewSignatureList(CERT_SHA256_GUID)
		if err := sl.AppendBytes(consistencyOwner, payload(32)); err != nil {
			t.Fatalf("fixture: %v", err)
		}
		return sl.Bytes()
	}()

	t.Run("exact size", func(t *testing.T) {
		if _, err := ReadSignatureList(bytes.NewReader(valid)); err != nil {
			t.Fatalf("valid list rejected: %v", err)
		}
	})

	t.Run("list smaller than header", func(t *testing.T) {
		raw := encodeHeader(CERT_SHA256_GUID, SizeofSignatureList-1, 0, 0)
		if _, err := ReadSignatureList(bytes.NewReader(raw)); !errors.Is(err, ErrInvalidSignatureList) {
			t.Fatalf("got %v, want ErrInvalidSignatureList", err)
		}
	})

	t.Run("list exactly header size", func(t *testing.T) {
		raw := encodeHeader(CERT_SHA256_GUID, SizeofSignatureList, 0, 0)
		sl, err := ReadSignatureList(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("empty list rejected: %v", err)
		}
		if len(sl.Signatures) != 0 || sl.ListSize != SizeofSignatureList {
			t.Fatalf("empty list parsed incorrectly")
		}
	})

	t.Run("list size above maximum", func(t *testing.T) {
		raw := encodeHeader(CERT_SHA256_GUID, MaxSignatureListSize+1, 0, 48)
		if _, err := ReadSignatureList(bytes.NewReader(raw)); !errors.Is(err, ErrInvalidSignatureList) {
			t.Fatalf("got %v, want ErrInvalidSignatureList", err)
		}
	})

	t.Run("nonzero header size", func(t *testing.T) {
		raw := encodeHeader(CERT_SHA256_GUID, SizeofSignatureList, 4, 48)
		if _, err := ReadSignatureList(bytes.NewReader(raw)); !errors.Is(err, ErrInvalidSignatureList) {
			t.Fatalf("got %v, want ErrInvalidSignatureList", err)
		}
	})

	t.Run("signature size smaller than owner", func(t *testing.T) {
		// The signature type rules reject this first for every known type;
		// the low level decoder must reject it as well when called directly.
		raw := encodeHeader(CERT_SHA256_GUID, SizeofSignatureList, 0, 8)
		if _, err := ReadSignatureList(bytes.NewReader(raw)); !errors.Is(err, ErrSigSizeMismatch) {
			t.Fatalf("got %v, want ErrSigSizeMismatch", err)
		}
		if _, err := ReadSignatureData(bytes.NewReader(payload(16)), util.SizeofEFIGUID-1); !errors.Is(err, ErrInvalidSignatureList) {
			t.Fatalf("got %v, want ErrInvalidSignatureList", err)
		}
		if _, err := ReadSignatureData(bytes.NewReader(payload(16)), util.SizeofEFIGUID); err != nil {
			t.Fatalf("owner only signature entry rejected: %v", err)
		}
	})

	t.Run("zero signature size with entries", func(t *testing.T) {
		raw := encodeHeader(CERT_SHA256_GUID, SizeofSignatureList+48, 0, 0)
		raw = append(raw, payload(48)...)
		if _, err := ReadSignatureList(bytes.NewReader(raw)); !errors.Is(err, ErrInvalidSignatureList) {
			t.Fatalf("got %v, want ErrInvalidSignatureList", err)
		}
	})

	t.Run("list size not a multiple of entry size", func(t *testing.T) {
		// 28 header + 48 entry + 1 dangling byte.
		raw := encodeHeader(CERT_SHA256_GUID, SizeofSignatureList+49, 0, 48)
		raw = append(raw, payload(49)...)
		if _, err := ReadSignatureList(bytes.NewReader(raw)); !errors.Is(err, ErrInvalidSignatureList) {
			t.Fatalf("got %v, want ErrInvalidSignatureList", err)
		}
	})

	t.Run("truncated list", func(t *testing.T) {
		if _, err := ReadSignatureList(bytes.NewReader(valid[:len(valid)-1])); !errors.Is(err, ErrInvalidSignatureList) {
			t.Fatalf("got %v, want ErrInvalidSignatureList", err)
		}
	})

	t.Run("truncated header", func(t *testing.T) {
		if _, err := ReadSignatureList(bytes.NewReader(valid[:10])); err == nil || errors.Is(err, io.EOF) {
			t.Fatalf("got %v, want a non EOF error", err)
		}
	})

	t.Run("unknown signature type", func(t *testing.T) {
		unknown := util.EFIGUID{Data1: 0xdeadbeef, Data2: 1, Data3: 2, Data4: [8]uint8{3, 4, 5, 6, 7, 8, 9, 10}}
		raw := encodeHeader(unknown, SizeofSignatureList, 0, 48)
		if _, err := ReadSignatureList(bytes.NewReader(raw)); err == nil {
			t.Fatalf("unknown type accepted")
		}
	})

	t.Run("declared size larger than data", func(t *testing.T) {
		// Claim two signatures but only supply one.
		raw := encodeHeader(CERT_SHA256_GUID, SizeofSignatureList+2*48, 0, 48)
		raw = append(raw, payload(48)...)
		if _, err := ReadSignatureList(bytes.NewReader(raw)); !errors.Is(err, ErrInvalidSignatureList) {
			t.Fatalf("got %v, want ErrInvalidSignatureList", err)
		}
	})
}

// TestReadSignatureDatabaseReportsTruncation verifies that a truncated
// database never looks like a clean end of input.
func TestReadSignatureDatabaseReportsTruncation(t *testing.T) {
	sl := NewSignatureList(CERT_SHA256_GUID)
	if err := sl.AppendBytes(consistencyOwner, payload(32)); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	enc := sl.Bytes()
	// A complete list followed by a partial list header must be an error.
	data := append(append([]byte{}, enc...), enc[:12]...)
	if _, err := ReadSignatureDatabase(bytes.NewReader(data)); err == nil {
		t.Fatalf("truncated database parsed as clean input")
	}
	// The complete list alone is fine.
	if _, err := ReadSignatureDatabase(bytes.NewReader(enc)); err != nil {
		t.Fatalf("complete database rejected: %v", err)
	}
}

// TestSignatureListAppendOverflow guards the 32 bit encoded list size.
func TestSignatureListAppendOverflow(t *testing.T) {
	sl := NewSignatureList(CERT_SHA256_GUID)
	sl.ListSize = ^uint32(0) - 8
	if err := sl.AppendBytes(consistencyOwner, payload(32)); !errors.Is(err, ErrInvalidSignatureList) {
		t.Fatalf("got %v, want ErrInvalidSignatureList", err)
	}
	if len(sl.Signatures) != 0 {
		t.Fatalf("list mutated on rejected append")
	}
}

// TestDatabaseAppendChoosesListBySize checks that appending picks a signature
// list that holds entries of the same size, and creates a new list otherwise.
func TestDatabaseAppendChoosesListBySize(t *testing.T) {
	db := NewSignatureDatabase()
	first := payload(32)
	second := payload(33)

	if err := db.Append(CERT_SHA256_GUID, consistencyOwner, first); err != nil {
		t.Fatalf("append first: %v", err)
	}
	if err := db.Append(CERT_SHA256_GUID, consistencyOwner, second); !errors.Is(err, ErrSigSizeMismatch) {
		t.Fatalf("append wrong size: got %v, want ErrSigSizeMismatch", err)
	}

	// X509 has a variable size: different sized certificates live in separate
	// lists so that every list keeps a single SignatureSize.
	db = NewSignatureDatabase()
	if err := db.Append(CERT_X509_GUID, consistencyOwner, payload(40)); err != nil {
		t.Fatalf("append cert a: %v", err)
	}
	if err := db.Append(CERT_X509_GUID, consistencyOwner, payload(41)); err != nil {
		t.Fatalf("append cert b: %v", err)
	}
	// A duplicate is reported, and it is not parked in a new list.
	if err := db.Append(CERT_X509_GUID, consistencyOwner, payload(40)); !errors.Is(err, ErrSigDataExists) {
		t.Fatalf("append cert a again: got %v, want ErrSigDataExists", err)
	}
	// A new certificate of an already present size joins that list.
	different := payload(40)
	different[0]++
	if err := db.Append(CERT_X509_GUID, consistencyOwner, different); err != nil {
		t.Fatalf("append cert c: %v", err)
	}
	if len(*db) != 2 {
		t.Fatalf("expected 2 lists, got %d", len(*db))
	}
	if len((*db)[0].Signatures) != 2 || len((*db)[1].Signatures) != 1 {
		t.Fatalf("wrong grouping: %d/%d", len((*db)[0].Signatures), len((*db)[1].Signatures))
	}
	if err := db.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

// TestDatabaseEditConsistency checks that database level edits are reflected in
// the encoded form and that a full edit cycle stays valid and readable.
func TestDatabaseEditConsistency(t *testing.T) {
	db := NewSignatureDatabase()
	for i := 0; i < 3; i++ {
		if err := db.Append(CERT_SHA256_GUID, consistencyOwner, append([]byte{byte(i)}, payload(31)...)); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if err := db.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	encoded := db.Bytes()
	read, err := ReadSignatureDatabase(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(read) != 1 || len(read[0].Signatures) != 3 {
		t.Fatalf("unexpected read shape")
	}
	if !bytes.Equal(read.Bytes(), encoded) {
		t.Fatalf("database round trip is not byte identical")
	}

	for i := 0; i < 3; i++ {
		if err := db.Remove(CERT_SHA256_GUID, consistencyOwner, append([]byte{byte(i)}, payload(31)...)); err != nil {
			t.Fatalf("remove %d: %v", i, err)
		}
		if len(*db) != 0 && 2-i != len((*db)[0].Signatures) {
			t.Fatalf("remove %d: %d signatures left", i, len((*db)[0].Signatures))
		}
	}
	if len(*db) != 0 {
		t.Fatalf("database not empty after removing every signature")
	}
	if len(db.Bytes()) != 0 {
		t.Fatalf("empty database encodes to bytes")
	}

	// Removing from an empty database is a failure path, not a panic.
	if err := db.Remove(CERT_SHA256_GUID, consistencyOwner, payload(32)); !errors.Is(err, ErrNotFoundSigList) {
		t.Fatalf("got %v, want ErrNotFoundSigList", err)
	}
	if err := db.RemoveSignature(CERT_X509_GUID, &SignatureData{Owner: consistencyOwner, Data: payload(40)}); !errors.Is(err, ErrNotFoundSigList) {
		t.Fatalf("got %v, want ErrNotFoundSigList", err)
	}
}

// TestDatabaseLookupIsTypeScoped checks that existence checks only consider the
// requested signature type.
func TestDatabaseLookupIsTypeScoped(t *testing.T) {
	data := payload(32)
	db := NewSignatureDatabase()
	if err := db.Append(CERT_SHA256_GUID, consistencyOwner, data); err != nil {
		t.Fatalf("append: %v", err)
	}
	if !db.BytesExists(CERT_SHA256_GUID, consistencyOwner, data) {
		t.Fatalf("present signature not found")
	}
	if db.BytesExists(CERT_SHA512_GUID, consistencyOwner, data) {
		t.Fatalf("signature found under the wrong signature type")
	}
	// The owner is part of a signature entry identity.
	other := consistencyOwner
	other.Data1++
	if db.BytesExists(CERT_SHA256_GUID, other, data) {
		t.Fatalf("signature matched with the wrong owner")
	}
}

// TestValidateRejectsInconsistentLists checks that hand assembled lists are
// rejected instead of being written out.
func TestValidateRejectsInconsistentLists(t *testing.T) {
	entry := util.SizeofEFIGUID + 32

	base := func() *SignatureList {
		sl := NewSignatureList(CERT_SHA256_GUID)
		if err := sl.AppendBytes(consistencyOwner, payload(32)); err != nil {
			t.Fatalf("fixture: %v", err)
		}
		return sl
	}

	cases := []struct {
		name   string
		mutate func(*SignatureList)
		want   error
	}{
		{"list size too large", func(sl *SignatureList) { sl.ListSize++ }, ErrInvalidSignatureList},
		{"list size too small", func(sl *SignatureList) { sl.ListSize-- }, ErrInvalidSignatureList},
		{"signature size wrong", func(sl *SignatureList) { sl.Size = entry + 1 }, ErrSigSizeMismatch},
		{"header size nonzero", func(sl *SignatureList) { sl.HeaderSize = 4 }, ErrInvalidSignatureList},
		{"entry payload mismatch", func(sl *SignatureList) { sl.Signatures[0].Data = payload(31) }, ErrSigSizeMismatch},
		{"unknown type", func(sl *SignatureList) {
			sl.SignatureType = util.EFIGUID{Data1: 1, Data2: 2, Data3: 3, Data4: [8]uint8{4, 5, 6, 7, 8, 9, 10, 11}}
		}, ErrNoSuchSignatureScheme},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sl := base()
			if err := sl.Validate(); err != nil {
				t.Fatalf("baseline: %v", err)
			}
			tc.mutate(sl)
			if err := sl.Validate(); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}

	// The database propagates the list level failure.
	db := SignatureDatabase{base(), base()}
	db[1].ListSize++
	if err := db.Validate(); err == nil {
		t.Fatalf("database accepted an invalid list")
	}
}

// TestSchemeRulesAreLive checks that rules registered or replaced after a list
// exists are applied to every subsequent operation.
func TestSchemeRulesAreLive(t *testing.T) {
	guid := util.EFIGUID{Data1: 0x1111, Data2: 0x2222, Data3: 0x3333, Data4: [8]uint8{1, 2, 3, 4, 5, 6, 7, 8}}
	defer UnregisterSignatureScheme(guid)

	if _, ok := LookupSignatureScheme(guid); ok {
		t.Fatalf("unknown guid already has a scheme")
	}
	sl := NewSignatureList(guid)
	if err := sl.AppendBytes(consistencyOwner, payload(32)); !errors.Is(err, ErrNoSuchSignatureScheme) {
		t.Fatalf("got %v, want ErrNoSuchSignatureScheme", err)
	}

	if err := RegisterSignatureScheme(SignatureScheme{GUID: guid, Type: "TEST", Size: util.SizeofEFIGUID + 32}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := sl.AppendBytes(consistencyOwner, payload(32)); err != nil {
		t.Fatalf("append under new rule: %v", err)
	}
	if err := sl.AppendBytes(consistencyOwner, payload(31)); !errors.Is(err, ErrSigSizeMismatch) {
		t.Fatalf("got %v, want ErrSigSizeMismatch", err)
	}
	encoded := sl.Bytes()
	if _, err := ReadSignatureList(bytes.NewReader(encoded)); err != nil {
		t.Fatalf("read under new rule: %v", err)
	}

	// Replacing the rule changes the meaning of the same list.
	if err := RegisterSignatureScheme(SignatureScheme{GUID: guid, Type: "TEST", Size: util.SizeofEFIGUID + 31}); err != nil {
		t.Fatalf("re-register: %v", err)
	}
	if err := sl.Validate(); !errors.Is(err, ErrSigSizeMismatch) {
		t.Fatalf("validate under replaced rule: got %v, want ErrSigSizeMismatch", err)
	}
	if _, err := ReadSignatureList(bytes.NewReader(encoded)); !errors.Is(err, ErrSigSizeMismatch) {
		t.Fatalf("read under replaced rule: got %v, want ErrSigSizeMismatch", err)
	}

	UnregisterSignatureScheme(guid)
	if _, ok := LookupSignatureScheme(guid); ok {
		t.Fatalf("scheme still registered after unregister")
	}
	if err := sl.AppendBytes(consistencyOwner, payload(32)); !errors.Is(err, ErrNoSuchSignatureScheme) {
		t.Fatalf("got %v, want ErrNoSuchSignatureScheme", err)
	}
}

// TestRegisterSignatureSchemeRejectsInvalidRules checks the registration
// boundary: an entry can never be smaller than its owner GUID.
func TestRegisterSignatureSchemeRejectsInvalidRules(t *testing.T) {
	guid := util.EFIGUID{Data1: 0x9999}
	defer UnregisterSignatureScheme(guid)

	if err := RegisterSignatureScheme(SignatureScheme{GUID: guid, Type: "TEST", Size: util.SizeofEFIGUID}); !errors.Is(err, ErrInvalidSignatureScheme) {
		t.Fatalf("got %v, want ErrInvalidSignatureScheme", err)
	}
	if err := RegisterSignatureScheme(SignatureScheme{GUID: guid, Type: "TEST"}); !errors.Is(err, ErrInvalidSignatureScheme) {
		t.Fatalf("got %v, want ErrInvalidSignatureScheme", err)
	}
	if err := RegisterSignatureScheme(SignatureScheme{GUID: guid, Size: util.SizeofEFIGUID + 1}); !errors.Is(err, ErrInvalidSignatureScheme) {
		t.Fatalf("got %v, want ErrInvalidSignatureScheme for a nameless unknown type", err)
	}
}

// TestDefaultSchemesAreComplete checks the built-in rule table against the
// public signature type list, so a newly added type cannot silently become
// unreadable.
func TestDefaultSchemesAreComplete(t *testing.T) {
	seen := map[CertType]bool{}
	for _, scheme := range RegisteredSignatureSchemes() {
		if scheme.Type == "" {
			t.Fatalf("%s has no name", scheme.GUID.Format())
		}
		if name, ok := ValidEFISignatureSchemes[scheme.GUID]; !ok {
			t.Fatalf("%s missing from ValidEFISignatureSchemes", scheme.GUID.Format())
		} else if name != scheme.Type {
			t.Fatalf("%s named %q in scheme and %q in map", scheme.GUID.Format(), scheme.Type, name)
		}
		if scheme.Size == 0 && scheme.MinSize < util.SizeofEFIGUID+1 {
			t.Fatalf("%s has an unusable minimum size %d", scheme.GUID.Format(), scheme.MinSize)
		}
		if scheme.Size != 0 && scheme.Size < util.SizeofEFIGUID+1 {
			t.Fatalf("%s has an unusable size %d", scheme.GUID.Format(), scheme.Size)
		}
		seen[scheme.Type] = true
	}
	// Sorted output is part of the contract.
	if !sort.SliceIsSorted(RegisteredSignatureSchemes(), func(i, j int) bool {
		return RegisteredSignatureSchemes()[i].GUID.Data1 < RegisteredSignatureSchemes()[j].GUID.Data1
	}) {
		t.Fatalf("registered schemes are not ordered")
	}
	for name := range ValidEFISignatureSchemes {
		if !seen[ValidEFISignatureSchemes[name]] {
			t.Fatalf("signature type %s has no rule", ValidEFISignatureSchemes[name])
		}
	}
}

// TestExternalManagementRoundTrip documents that externally managed entries
// keep their payload; dropping it would corrupt the list on re-encoding.
func TestExternalManagementRoundTrip(t *testing.T) {
	sl := NewSignatureList(CERT_EXTERNAL_MANAGEMENT_GUID)
	if err := sl.AppendBytes(consistencyOwner, []byte{1}); err != nil {
		t.Fatalf("append: %v", err)
	}
	got, err := ReadSignatureList(bytes.NewReader(sl.Bytes()))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got.Signatures) != 1 || !bytes.Equal(got.Signatures[0].Data, []byte{1}) {
		t.Fatalf("external management payload was dropped")
	}
	if !bytes.Equal(got.Bytes(), sl.Bytes()) {
		t.Fatalf("external management list does not round trip")
	}
}

// encodeHeader builds an EFI_SIGNATURE_LIST header without any signature data.
func encodeHeader(guid util.EFIGUID, listSize, headerSize, size uint32) []byte {
	buf := new(bytes.Buffer)
	for _, v := range []interface{}{guid, listSize, headerSize, size} {
		if err := binary.Write(buf, binary.LittleEndian, v); err != nil {
			panic(err)
		}
	}
	return buf.Bytes()
}

// encodeList builds a full EFI_SIGNATURE_LIST with a single signature entry of
// the supplied payload.
func encodeList(t *testing.T, guid util.EFIGUID, listSize, headerSize, size uint32, data []byte) []byte {
	t.Helper()
	raw := encodeHeader(guid, listSize, headerSize, size)
	if headerSize > 0 {
		raw = append(raw, make([]byte, headerSize)...)
	}
	return append(raw, data...)
}

// TestReencodingIsStableAfterEdits serializes an edited database, reads it back
// and compares it with the in-memory representation field by field. Reading and
// editing must agree on the encoded form for every signature type.
func TestReencodingIsStableAfterEdits(t *testing.T) {
	db := NewSignatureDatabase()
	for _, tc := range fixedSignatureTypes() {
		if err := db.Append(tc.guid, consistencyOwner, payload(tc.length)); err != nil {
			t.Fatalf("append %s: %v", tc.name, err)
		}
	}
	// Two more entries in an existing list, and an X509 list with a variable
	// size, to exercise grouping and removal alongside fixed sizes.
	if err := db.Append(CERT_SHA256_GUID, consistencyOwner, payload(32)); !errors.Is(err, ErrSigDataExists) {
		t.Fatalf("duplicate sha256: got %v, want ErrSigDataExists", err)
	}
	another := payload(32)
	another[0]++
	if err := db.Append(CERT_SHA256_GUID, consistencyOwner, another); err != nil {
		t.Fatalf("append sha256: %v", err)
	}
	if err := db.Append(CERT_X509_GUID, consistencyOwner, payload(300)); err != nil {
		t.Fatalf("append x509: %v", err)
	}
	if err := db.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	encoded := db.Bytes()
	read, err := ReadSignatureDatabase(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(read) != len(*db) {
		t.Fatalf("list count: got %d want %d", len(read), len(*db))
	}
	for i := range *db {
		want, got := (*db)[i], read[i]
		if want.ListSize != got.ListSize || want.Size != got.Size ||
			want.HeaderSize != got.HeaderSize ||
			!bytes.Equal(want.SignatureHeader, got.SignatureHeader) ||
			len(want.Signatures) != len(got.Signatures) {
			t.Fatalf("list %d changed on round trip", i)
		}
		for j := range want.Signatures {
			if !util.CmpEFIGUID(want.Signatures[j].Owner, got.Signatures[j].Owner) ||
				!bytes.Equal(want.Signatures[j].Data, got.Signatures[j].Data) {
				t.Fatalf("list %d signature %d changed on round trip", i, j)
			}
		}
	}
	if err := read.Validate(); err != nil {
		t.Fatalf("validate re-read: %v", err)
	}
	if !bytes.Equal(read.Bytes(), encoded) {
		t.Fatalf("re-encoding differs from the original encoding")
	}

	// Removing through the re-read copy yields exactly the original minus one.
	if err := read.Remove(CERT_SHA256_GUID, consistencyOwner, another); err != nil {
		t.Fatalf("remove from re-read database: %v", err)
	}
	if err := read.Validate(); err != nil {
		t.Fatalf("validate after remove: %v", err)
	}
}

// TestAPIAcceptsLegacyMultihashList covers a list with several entries and a
// large but legal count, to show the reader does not cap the number of
// signatures it accepts.
func TestAPIAcceptsLegacyMultihashList(t *testing.T) {
	sl := NewSignatureList(CERT_SHA256_GUID)
	for i := 0; i < 1500; i++ {
		data := payload(32)
		binary.LittleEndian.PutUint32(data, uint32(i))
		if err := sl.AppendBytes(consistencyOwner, data); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	got, err := ReadSignatureList(bytes.NewReader(sl.Bytes()))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got.Signatures) != 1500 {
		t.Fatalf("signature count: got %d want 1500", len(got.Signatures))
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

// TestResetSignatureSchemesRestoresDefaults checks that a registration can be
// rolled back and that the default rules become active again.
func TestResetSignatureSchemesRestoresDefaults(t *testing.T) {
	guid := util.EFIGUID{Data1: 0x4242}
	if err := RegisterSignatureScheme(SignatureScheme{GUID: guid, Type: "TEMP", Size: util.SizeofEFIGUID + 5}); err != nil {
		t.Fatalf("register: %v", err)
	}
	ResetSignatureSchemes()
	defer ResetSignatureSchemes()

	if _, ok := LookupSignatureScheme(guid); ok {
		t.Fatalf("temporary scheme survived a reset")
	}
	for _, tc := range fixedSignatureTypes() {
		scheme, ok := LookupSignatureScheme(tc.guid)
		if !ok {
			t.Fatalf("%s lost its default rule after a reset", tc.name)
		}
		if scheme.Size != util.SizeofEFIGUID+uint32(tc.length) {
			t.Fatalf("%s: default size changed to %d", tc.name, scheme.Size)
		}
	}
}

// TestMaxSignatureListSizeIsLive checks the allocation guard can be lowered,
// that the new limit applies to the next read, and that restoring it works.
func TestMaxSignatureListSizeIsLive(t *testing.T) {
	old := MaxSignatureListSize
	defer func() { MaxSignatureListSize = old }()

	sl := NewSignatureList(CERT_SHA256_GUID)
	for i := 0; i < 4; i++ {
		data := payload(32)
		data[0] = byte(i)
		if err := sl.AppendBytes(consistencyOwner, data); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	encoded := sl.Bytes()
	if _, err := ReadSignatureList(bytes.NewReader(encoded)); err != nil {
		t.Fatalf("read under default limit: %v", err)
	}

	// A limit below the encoded size rejects the very same list.
	MaxSignatureListSize = sl.ListSize - 1
	if _, err := ReadSignatureList(bytes.NewReader(encoded)); !errors.Is(err, ErrInvalidSignatureList) {
		t.Fatalf("got %v, want ErrInvalidSignatureList", err)
	}

	// A limit equal to the encoded size accepts it: the boundary is inclusive.
	MaxSignatureListSize = sl.ListSize
	if _, err := ReadSignatureList(bytes.NewReader(encoded)); err != nil {
		t.Fatalf("read at exact limit: %v", err)
	}
}

// TestLegacySchemeLookup checks that a GUID known only through the public
// ValidEFISignatureSchemes map is still readable and editable as a variable
// length signature type.
func TestLegacySchemeLookup(t *testing.T) {
	guid := util.EFIGUID{Data1: 0x5151, Data2: 7, Data3: 8, Data4: [8]uint8{9}}
	ValidEFISignatureSchemes[guid] = "LEGACY"
	defer delete(ValidEFISignatureSchemes, guid)

	scheme, ok := LookupSignatureScheme(guid)
	if !ok {
		t.Fatalf("legacy guid not found")
	}
	if scheme.Size != 0 || scheme.MinSize != util.SizeofEFIGUID+1 {
		t.Fatalf("unexpected legacy rules: %+v", scheme)
	}

	sl := NewSignatureList(guid)
	if err := sl.AppendBytes(consistencyOwner, payload(5)); err != nil {
		t.Fatalf("append: %v", err)
	}
	if _, err := ReadSignatureList(bytes.NewReader(sl.Bytes())); err != nil {
		t.Fatalf("read: %v", err)
	}
}

// TestSignatureEntrySizeTable pins the exact encoded EFI_SIGNATURE_DATA size
// documented by the UEFI specification for every signature type. It is the
// single reviewable table of the length boundary: 16 byte SignatureOwner plus
// the payload documented in MdePkg/Include/Guid/ImageAuthentication.h.
func TestSignatureEntrySizeTable(t *testing.T) {
	want := map[CertType]uint32{
		CERT_SHA1:                16 + 20,
		CERT_SHA224:              16 + 28,
		CERT_SHA256:              16 + 32,
		CERT_SHA384:              16 + 48,
		CERT_SHA512:              16 + 64,
		CERT_SM3:                 16 + 32,
		CERT_RSA2048:             16 + 256,
		CERT_RSA2048_SHA1:        16 + 256,
		CERT_RSA2048_SHA256:      16 + 256,
		CERT_X509_SHA256:         16 + 48,
		CERT_X509_SHA384:         16 + 64,
		CERT_X509_SHA512:         16 + 80,
		CERT_X509_SM3:            16 + 48,
		CERT_EXTERNAL_MANAGEMENT: 16 + 1,
	}
	seen := map[CertType]bool{}
	for _, scheme := range RegisteredSignatureSchemes() {
		if scheme.Size == 0 {
			continue // variable length types are checked below
		}
		expected, ok := want[scheme.Type]
		if !ok {
			continue
		}
		seen[scheme.Type] = true
		if scheme.Size != expected {
			t.Fatalf("%s: entry size %d, want %d", scheme.Type, scheme.Size, expected)
		}
	}
	for name := range want {
		if !seen[name] {
			t.Fatalf("%s: no fixed size rule found", name)
		}
	}

	// X509 certificates are the only variable length signature type. The
	// smallest entry is a one byte certificate behind the owner GUID.
	x509, ok := LookupSignatureScheme(CERT_X509_GUID)
	if !ok {
		t.Fatalf("X509 has no scheme")
	}
	if x509.Size != 0 || x509.MinSize != 17 {
		t.Fatalf("X509: size %d min size %d, want variable with min 17", x509.Size, x509.MinSize)
	}
}
