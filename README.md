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

## Read and edit signature databases of every type

`SignatureList` and `SignatureDatabase` accept every signature type defined by
the UEFI specification (SHA-1/224/256/384/512, SM3, the RSA-2048 variants,
X.509, and the X.509 revocation and external management entries). The length
rules of each type apply to reading, appending and removing alike, so an entry
you append is exactly what a later read returns.

```go
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/go-uefi/efi/util"
)

func main() {
	db := signature.NewSignatureDatabase()

	hash := make([]byte, 32) // SHA-256 of an image
	if err := db.Append(signature.CERT_SHA256_GUID, util.EFIGUID{}, hash); err != nil {
		log.Fatal(err)
	}

	// PEM certificates are normalized to DER on the way in.
	pemBytes, _ := os.ReadFile("signing.cert")
	if err := db.Append(signature.CERT_X509_GUID, util.EFIGUID{}, pemBytes); err != nil {
		log.Fatal(err)
	}

	// Failed edits leave the database untouched and return a sentinel error.
	if err := db.Append(signature.CERT_SHA256_GUID, util.EFIGUID{}, hash[:16]); err != nil {
		fmt.Println("rejected:", err) // signature data size does not match the signature type
	}

	// Validate before writing a database assembled by hand.
	if err := db.Validate(); err != nil {
		log.Fatal(err)
	}
	if err := db.Remove(signature.CERT_SHA256_GUID, util.EFIGUID{}, hash); err != nil {
		log.Fatal(err)
	}
}
```

`MaxSignatureListSize` bounds the size a parser is willing to allocate for one
signature list, and `RegisterSignatureScheme` installs the length rules for a
signature type that is not handled by default. Both are consulted on every
operation, so a changed rule applies to subsequent reads and edits.

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
