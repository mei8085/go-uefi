go-uefi
=======

A UEFI library written to interact with Linux efivars. The goal is to provide a
Go library to enable application authors to better utilize secure boot and UEFI.
This also includes unit-testing to ensure the library is compatible with
existing tools, and integration tests to ensure the library is able of deal with
future UEFI revisions.


# Features
* Implements most Secure Boot relevant structs as defined in UEFI Spec Version 2.8 Errata A (February 14th 2020).
* PE/COFF Checksumming.
* Microsoft Authenticode signing.
* A subset of PKCS7
* Working with EFI_SIGNATURE_LIST and EFI_SIGNATURE_DATABASE.
* Offline Secure Boot admission: decide if an EFI image executes under a given db/dbx policy, honoring certificate chains, hash entries and revocations.
* Integration tests utilizing [vmtest](https://github.com/hugelgupf/vmtest) and tianocore.
* Virtual filesystem support for easier testing.


# Examples

Some example can be found under `cmd/`.

# Code Examples

## Append signatures to db

```go
package main
import (
	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/go-uefi/efi/util"
	"github.com/foxboron/go-uefi/efivar"
	"github.com/foxboron/go-uefi/efivarfs"
)

var (
    cert, _ = util.ReadKeyFromFile("signing.key")
    key, _ = util.ReadCertFromFile("signing.cert")
    sigdata = signature.SignatureData{
	    Owner: util.EFIGUID{Data1: 0xc1095e1b, Data2: 0x8a3b, Data3: 0x4cf5, Data4: [8]uint8{0x9d, 0x4a, 0xaf, 0xc7, 0xd7, 0x5d, 0xca, 0x68}},
	    Data:  []uint8{}}
)

func main() {
	efifs := efivarfs.NewFS().Open()
	db, _ := efifs.Getdb()
	db.AppendSignature(signature.CERT_SHA256_GUID, &sigdata)
	efifs.WriteSignedUpdate(efivar.Db, db, key, cert)
}
```

## Use a in-memory efivarfs for tests

```go
package main
import (
	"github.com/foxboron/go-uefi/efi"
	"github.com/foxboron/go-uefi/efi/efitest"
	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/go-uefi/efivarfs"
)

func TestSecureBootOn(t *testing.T) {
	efifs := efivarfs.NewTestFS().
		With(efitest.SecureBootOn()).
		Open()
	ok, err := efifs.GetSetupMode()
	if err != nil {
		t.Fatalf("%v", err)
	}
	if !ok {
		t.Fatalf("Secure Boot is not enabled")
	}
}
```

## Sign UEFI binary
```go
package main
import (
	"github.com/foxboron/go-uefi/authenticode"
	"github.com/foxboron/go-uefi/efi/util"
)

var (
	key, _ := util.ReadKeyFromFile("signing.key")
	cert, _ := util.ReadCertFromFile("signing.cert")
)

func main(){
	peFile, _ := os.ReadFile("somefile")
	file, _ := authenticode.Parse(peFile)
	file.Sign(key, cert)
	os.WriteFile("somefile.signed", file.Bytes(), 0644)
}
```

## Check if an EFI image is admitted by a Secure Boot policy

The `efi/secureboot` package evaluates an image offline against the authorized
(`db`) and forbidden (`dbx`) signature databases. A revoked hash or certificate
in `dbx` always denies the image; otherwise a valid Authenticode chain to a
certificate in `db`, or a matching image hash in `db`, admits it. The verdict is
independent of how the databases are encoded or ordered.

```go
package main

import (
	"bytes"
	"os"

	"github.com/foxboron/go-uefi/efi/secureboot"
	"github.com/foxboron/go-uefi/efi/signature"
)

func main() {
	image, _ := os.Open("image.efi")
	defer image.Close()

	dbBytes, _ := os.ReadFile("db.esl")
	dbxBytes, _ := os.ReadFile("dbx.esl")

	db, _ := signature.ReadSignatureDatabase(bytes.NewReader(dbBytes))
	dbx, _ := signature.ReadSignatureDatabase(bytes.NewReader(dbxBytes))

	allowed, err := secureboot.VerifyImageReader(image, &db, &dbx)
	if err != nil || !allowed {
		// Image is denied (unsigned, revoked, or untrusted); err explains why.
		panic(err)
	}
}
```

The `cmd/gosecureboot` command wraps this for shell use:

```sh
gosecureboot -db db.esl -dbx dbx.esl image.efi
# prints ALLOWED (exit 0) or DENIED: <reason> (exit 1)
```

## Checksum UEFI executable
```go
package main
import (
	"github.com/foxboron/go-uefi/authenticode"
)

func main(){
	peFile, _ := os.ReadFile("somefile")
	file, _ := authenticode.Parse(peFile)
	checksum := file.Hash(crypto.SHA256)
	fmt.Printf("%x\n", checksum)
}
```
