package main

import (
	"crypto/rand"
	"encoding/gob"
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"

	kzg "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
)

func main() {
	const power = 15        // e.g., 2^15 = 32768 constraints
	const size = 1 << power // must be power of 2

	alpha, err := rand.Int(rand.Reader, ecc.BN254.ScalarField())
	
	if err != nil {
		panic(err)
	}

	srs, _ := kzg.NewSRS(size, alpha)

	// Write SRS to file
	file, err := os.Create("srs.gob")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	encoder := gob.NewEncoder(file)
	if err := encoder.Encode(srs); err != nil {
		panic(err)
	}

	fmt.Println("✅ SRS written to srs.gob")

}
