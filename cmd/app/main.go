package main

import (
	"encoding/gob"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	kzg "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	"github.com/consensys/gnark/backend/plonk"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"os"
	"github.com/consensys/gnark-crypto/kzg/bn254"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
)

type Input = frontend.Variable
type API = frontend.API

// define circuit inputs
type Circuit struct {
	A Input `gnark:"a"`
	B Input `gnark:"b"`
	C Input `gnark:"c,public"`
}

// define circuit constraints
func (circuit *Circuit) Define(api API) error {
	// a2 := api.Mul(circuit.A, circuit.A)
	// b2 := api.Mul(circuit.B, circuit.B)
	// c2 := api.Mul(circuit.C, circuit.C)
	lhs := api.Add(api.Mul(circuit.A, circuit.B), api.Mul(circuit.A, circuit.B))
	api.AssertIsEqual(lhs, circuit.C)
	return nil
}

// Serializes the proof in an 0x prefixed hexstring
func SerializeProofSolidityBn254(proof plonk.Proof) string {
	buf := proof.(*plonk_bn254.Proof).MarshalSolidity()
	return hexutil.Encode(buf)
}

func ReadSRS(path string) (*kzg.SRS, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var srs kzg.SRS
	decoder := gob.NewDecoder(file)
	if err := decoder.Decode(&srs); err != nil {
		return nil, err
	}
	return &srs, nil
}



// Read and compute Lagrange basis
func ReadSRSWithLagrange(path string) (*kzg.SRS, []ecc.bn254.G1Affine, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	var srs kzg.SRS
	decoder := gob.NewDecoder(file)
	if err := decoder.Decode(&srs); err != nil {
		return nil, nil, err
	}

	// Compute Lagrange basis from monomial G1 points
	domain := fft.NewDomain(uint64(len(srs.G1)), nil) // size must match srs.G1
	srsLagrange := make([]bn254.G1Affine, len(srs.G1))
	copy(srsLagrange, srs.G1)
	fft.BitReverse(srsLagrange)           // required by FFT
	fft.FFT(srsLagrange, domain, fft.DIF) // FFT to Lagrange basis
	return &srs, srsLagrange, nil
}


func main() {

	var circuit Circuit

	scalarField := ecc.BN254.ScalarField()

	// compile circuit
	ccs, err := frontend.Compile(scalarField, scs.NewBuilder, &circuit)
	if err != nil {
		fmt.Println(err)
	}

	/*
		srs, srsLagrange, err := unsafekzg.NewSRS(ccs.(*cs.SparseR1CS))
		if err != nil {
			fmt.Println(err)
		}*/

	s, err := ReadSRS("srs.gob")
	srs, srsLagrange, err := s.ReadFrom()

	{
		var w Circuit
		w.A = 5
		w.B = 12
		w.C = 120

		witnessFull, err := frontend.NewWitness(&w, scalarField)
		if err != nil {
			fmt.Println(err)
		}

		witnessPublic, err := frontend.NewWitness(&w, scalarField, frontend.PublicOnly())

		if err != nil {
			fmt.Println(err)
		}

		pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
		if err != nil {
			fmt.Println(err)
		}

		verifierPath, err := os.Create("Verifier.sol")
		if err != nil {
			fmt.Println(err)
		}

		err = vk.ExportSolidity(verifierPath)
		if err != nil {
			fmt.Println(err)
		}

		proof, err := plonk.Prove(ccs, pk, witnessFull)
		if err != nil {
			fmt.Println(err)
		}

		// 🔧 Marshal to Solidity format
		calldata := SerializeProofSolidityBn254(proof)
		fmt.Println(calldata)

		err = plonk.Verify(proof, vk, witnessPublic)
		if err != nil {
			fmt.Println("❌ Proof verification failed:", err)
		} else {
			fmt.Println("✅ Proof verified successfully!")
		}
	}
}
