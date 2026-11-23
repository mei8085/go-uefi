package signature

import (
	"bytes"
	"io"
	"reflect"

	"github.com/foxboron/go-uefi/efi/util"
	"github.com/pkg/errors"
)

// SignatureDatabase is a list of EFI signature lists
type SignatureDatabase []*SignatureList

var ErrNotFoundSigList = errors.New("signature list not found")

func NewSignatureDatabase() *SignatureDatabase {
	return &SignatureDatabase{}
}

// Checks if all signatures in a list is present in the signature database
func (sd *SignatureDatabase) SigDataExists(certtype util.EFIGUID, sigdata *SignatureData) bool {
	if sigdata == nil {
		return false
	}
	for _, sdsiglist := range *sd {
		if !util.CmpEFIGUID(sdsiglist.SignatureType, certtype) {
			continue
		}
		if ok, _ := sdsiglist.Exists(sigdata); ok {
			return true
		}
	}
	return false
}

// Checks if all signatures in a list is present in the signature database
func (sd *SignatureDatabase) Exists(certtype util.EFIGUID, siglist *SignatureList) bool {
	if siglist == nil {
		return false
	}
	for _, sdsiglist := range *sd {
		if !sdsiglist.CmpHeader(siglist) {
			continue
		}
		return sdsiglist.ExistsInList(siglist)
	}
	return false
}

// Checks if the bytes in a list is present in the signature database
func (sd *SignatureDatabase) BytesExists(certtype util.EFIGUID, owner util.EFIGUID, data []byte) bool {
	return sd.SigDataExists(certtype, &SignatureData{Owner: owner, Data: data})
}

// entrySizeFor returns the encoded size of data for certtype, applying the
// signature type rules (PEM normalization included).
func entrySizeFor(certtype util.EFIGUID, data []byte) (uint32, error) {
	scheme, ok := LookupSignatureScheme(certtype)
	if !ok {
		return 0, ErrNoSuchSignatureScheme
	}
	data = normalizeSignatureData(scheme, data)
	return validateSignatureData(scheme, data)
}

// Appends the raw signature values to the database
func (sd *SignatureDatabase) Append(certtype util.EFIGUID, owner util.EFIGUID, data []byte) error {
	size, err := entrySizeFor(certtype, data)
	if err != nil {
		return err
	}
	for _, l := range *sd {
		if !util.CmpEFIGUID(l.SignatureType, certtype) {
			continue
		}
		// A signature list has a single signature size. Only lists that hold
		// the same size of signature can take this entry. An empty list has no
		// size yet and can adopt the entry.
		if l.Size != size && !(l.Size == 0 && len(l.Signatures) == 0) {
			continue
		}
		// A duplicate is reported as an error so callers can tell an append
		// apart from a no-op; the list is left untouched either way.
		if err := l.AppendSignature(SignatureData{Owner: owner, Data: data}); err != nil {
			return err
		}
		return nil
	}
	sl := NewSignatureList(certtype)
	if err := sl.AppendBytes(owner, data); err != nil {
		return err
	}
	*sd = append(*sd, sl)
	return nil
}

// Appends a signaure to the database. It will scan the database for the appropriate list to append
// itself to.
func (sd *SignatureDatabase) AppendSignature(certtype util.EFIGUID, sl *SignatureData) error {
	if sl == nil {
		return errors.Wrapf(ErrInvalidSignatureList, "nil signature data")
	}
	return sd.Append(certtype, sl.Owner, sl.Data)
}

// Appends a signature list to the database
//
// The list is appended as-is; use Validate to check the database before it is
// written to a variable.
func (sd *SignatureDatabase) AppendList(sl *SignatureList) {
	if sl == nil {
		return
	}
	*sd = append(*sd, sl)
}

// Appends a signature database
func (sd *SignatureDatabase) AppendDatabase(s *SignatureDatabase) {
	if s == nil {
		return
	}
	for _, list := range *s {
		sd.AppendList(list)
	}
}

// Validate checks every signature list in the database against the safety
// rules of its signature type. A database edited through Append/Remove always
// validates; this catches lists that were assembled or parsed by hand.
func (sd *SignatureDatabase) Validate() error {
	for index, list := range *sd {
		if list == nil {
			return errors.Wrapf(ErrInvalidSignatureList, "signature list %d is nil", index)
		}
		if err := list.Validate(); err != nil {
			return errors.Wrapf(err, "signature list %d", index)
		}
	}
	return nil
}

// Remove the raw signature values to the database
func (sd *SignatureDatabase) Remove(certtype util.EFIGUID, owner util.EFIGUID, data []byte) error {
	scheme, ok := LookupSignatureScheme(certtype)
	if !ok {
		return ErrNoSuchSignatureScheme
	}
	data = normalizeSignatureData(scheme, data)
	size := util.SizeofEFIGUID + uint32(len(data))
	// We might want to differentiate between not finding a list for the type and
	// not finding appropriate sigdata in the different lists.
	nosigdata := false
	for _, l := range *sd {
		if !util.CmpEFIGUID(l.SignatureType, certtype) {
			continue
		}
		if size != l.Size {
			continue
		}
		if err := l.RemoveBytes(owner, data); errors.Is(err, ErrNotFoundSigData) {
			nosigdata = true
			continue
		} else if err != nil {
			return err
		}
		if len(l.Signatures) == 0 {
			return sd.RemoveList(l)
		}
		return nil
	}
	if nosigdata {
		return ErrNotFoundSigData
	}
	return ErrNotFoundSigList
}

// Removes a signaure to the database. It will scan available lists for something to remove
func (sd *SignatureDatabase) RemoveSignature(certtype util.EFIGUID, sl *SignatureData) error {
	if sl == nil {
		return errors.Wrapf(ErrInvalidSignatureList, "nil signature data")
	}
	return sd.Remove(certtype, sl.Owner, sl.Data)
}

func (sd *SignatureDatabase) removeslice(index int) {
	if len(*sd) == 1 {
		*sd = SignatureDatabase{}
		return
	}
	*sd = append((*sd)[:index], (*sd)[index+1:]...)
}

// Removes a signature list from the database
func (sd *SignatureDatabase) RemoveList(sl *SignatureList) error {
	for index, siglist := range *sd {
		if reflect.DeepEqual(sl, siglist) {
			sd.removeslice(index)
			return nil
		}
	}
	return ErrNotFoundSigList
}

// Serialize the Signature Database into bytes
func (sd *SignatureDatabase) Bytes() []byte {
	buf := new(bytes.Buffer)
	WriteSignatureDatabase(buf, *sd)
	return buf.Bytes()
}

func (sd *SignatureDatabase) Marshal(b *bytes.Buffer) {
	WriteSignatureDatabase(b, *sd)
}

func (sd *SignatureDatabase) Unmarshal(b *bytes.Buffer) error {
	s, err := ReadSignatureDatabase(b)
	if err != nil {
		return err
	}
	*sd = s
	return nil
}

// Write a signature database which contains a slice of SignautureLists
func WriteSignatureDatabase(b io.Writer, sigdb SignatureDatabase) {
	for _, l := range sigdb {
		if l == nil {
			continue
		}
		WriteSignatureList(b, *l)
	}
}

// Reads several signature lists from a io.Reader. It assumes io.EOF means there
// are no more signatures to read as opposed to an actual issue
func ReadSignatureDatabase(f io.Reader) (SignatureDatabase, error) {
	siglist := []*SignatureList{}
	for {
		sig, err := ReadSignatureList(f)
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return siglist, errors.Wrapf(err, "failed to parse signature lists")
		}
		siglist = append(siglist, sig)
	}
	return siglist, nil
}
