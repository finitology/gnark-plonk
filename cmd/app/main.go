package main

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"os"
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
	a2 := api.Mul(circuit.A, circuit.A)
	b2 := api.Mul(circuit.B, circuit.B)
	c2 := api.Mul(circuit.C, circuit.C)
	lhs := api.Add(a2, b2)
	api.AssertIsEqual(lhs, c2)
	return nil
}

// Serializes the proof in an 0x prefixed hexstring
func SerializeProofSolidityBn254(proof plonk.Proof) string {
	buf := proof.(*plonk_bn254.Proof).MarshalSolidity()
	return hexutil.Encode(buf)
}

func main() {

	var circuit Circuit

	scalarField := ecc.BN254.ScalarField()

	// compile circuit
	ccs, err := frontend.Compile(scalarField, scs.NewBuilder, &circuit)
	if err != nil {
		fmt.Println(err)
	}

	srs, srsLagrange, err := unsafekzg.NewSRS(ccs.(*cs.SparseR1CS))
	if err != nil {
		fmt.Println(err)
	}

	{
		var w Circuit
		w.A = 3
		w.B = 4
		w.C = 5

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
