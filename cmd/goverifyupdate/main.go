package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/foxboron/go-uefi/efi/attributes"
	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/go-uefi/efivar"
)

// goverifyupdate verifies an EFI_VARIABLE_AUTHENTICATION2 secure boot
// variable update package offline against the enrolled key databases,
// following the PK -> KEK -> db/dbx authorization hierarchy.
//
// On success it prints the authorizing signer and optionally writes the
// canonical variable state to an output file.
func main() {
	variable := flag.String("var", "", "Variable the update applies to: PK, KEK, db or dbx")
	pkFile := flag.String("pk", "", "Enrolled PK signature database (optional)")
	kekFile := flag.String("kek", "", "Enrolled KEK signature database (optional)")
	dbFile := flag.String("db", "", "Enrolled db signature database (optional)")
	dbxFile := flag.String("dbx", "", "Enrolled dbx signature database (optional)")
	appendWrite := flag.Bool("append", false, "Verify an append update (EFI_VARIABLE_APPEND_WRITE)")
	flag.Parse()

	args := flag.Args()
	if *variable == "" || len(args) < 1 {
		fmt.Println("goverifyupdate: -var <PK|KEK|db|dbx> [-pk file] [-kek file] [-db file] [-dbx file] [-append] <update.auth> [output]")
		os.Exit(1)
	}

	readDB := func(path string) *signature.SignatureDatabase {
		if path == "" {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			log.Fatal(err)
		}
		db, err := signature.ReadSignatureDatabase(bytes.NewReader(b))
		if err != nil {
			log.Fatalf("failed parsing %s: %v", path, err)
		}
		return &db
	}

	var v efivar.Efivar
	switch *variable {
	case "PK":
		v = efivar.PK
	case "KEK":
		v = efivar.KEK
	case "db":
		v = efivar.Db
	case "dbx":
		v = efivar.Dbx
	default:
		log.Fatalf("unknown variable %q: expected PK, KEK, db or dbx", *variable)
	}
	if *appendWrite {
		v.Attributes |= attributes.EFI_VARIABLE_APPEND_WRITE
	}

	payload, err := os.ReadFile(args[0])
	if err != nil {
		log.Fatal(err)
	}

	store := signature.NewAuthVariableStore(
		readDB(*pkFile),
		readDB(*kekFile),
		readDB(*dbFile),
		readDB(*dbxFile),
	)

	update, err := store.VerifyUpdate(v, payload)
	if err != nil {
		log.Fatalf("update rejected: %v", err)
	}

	fmt.Printf("update authorized by %q (timestamp %s)\n", update.Signer.Subject, update.Timestamp.Format())

	if len(args) == 2 {
		if err := os.WriteFile(args[1], update.Bytes(), 0o644); err != nil {
			log.Fatal(err)
		}
	}
}
