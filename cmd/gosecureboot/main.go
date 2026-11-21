// gosecureboot decides offline whether an EFI image is admitted by a Secure
// Boot policy. It takes the authorized (db) and forbidden (dbx) signature
// databases as raw EFI signature lists, exactly as stored in the corresponding
// EFI variables.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"

	"github.com/foxboron/go-uefi/efi/secureboot"
	"github.com/foxboron/go-uefi/efi/signature"
)

func main() {
	dbPath := flag.String("db", "", "authorized signature database (db), raw EFI signature list")
	dbxPath := flag.String("dbx", "", "forbidden signature database (dbx), raw EFI signature list (optional)")
	flag.Parse()

	args := flag.Args()
	if *dbPath == "" || len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: gosecureboot -db <db.esl> [-dbx <dbx.esl>] <image.efi>")
		os.Exit(2)
	}

	db, err := readDatabase(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed reading db: %v\n", err)
		os.Exit(2)
	}

	var dbx *signature.SignatureDatabase
	if *dbxPath != "" {
		dbx, err = readDatabase(*dbxPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed reading dbx: %v\n", err)
			os.Exit(2)
		}
	}

	image, err := os.Open(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed opening image: %v\n", err)
		os.Exit(2)
	}
	defer image.Close()

	ok, err := secureboot.VerifyImageReader(image, db, dbx)
	if err != nil {
		fmt.Printf("DENIED: %v\n", err)
		os.Exit(1)
	}
	if !ok {
		fmt.Println("DENIED")
		os.Exit(1)
	}
	fmt.Println("ALLOWED")
}

func readDatabase(path string) (*signature.SignatureDatabase, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sd, err := signature.ReadSignatureDatabase(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	return &sd, nil
}
