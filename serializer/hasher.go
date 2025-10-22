package serializer

import (
	"fmt"
	"hash/fnv"
	"strconv"

	"golang.org/x/tools/go/ssa"
)

// Hashes an ssa.Function into a string
func hashFunction(f *ssa.Function) string {
	if f == nil {
		return ""
	}
	// Hash the function based on name, package, signature, and instructions
	h := fnv.New64a()
	h.Write([]byte(f.Name()))
	if f.Pkg != nil && f.Pkg.Pkg != nil {
		h.Write([]byte(f.Pkg.Pkg.Path()))
	}
	h.Write([]byte(f.Signature.String()))
	for _, block := range f.Blocks {
		for _, instr := range block.Instrs {
			h.Write([]byte(instr.String()))
		}
	}
	return fmt.Sprintf("%x", h.Sum64())
}

// Hashes an ssa.CallInstruction into a string
func hashCallSite(ci ssa.CallInstruction) string {
	if ci == nil {
		return ""
	}

	h := fnv.New64a()
	if ci.Parent() != nil {
		h.Write([]byte(ci.Parent().Name()))
	}
	h.Write([]byte(ci.String()))
	h.Write([]byte(strconv.Itoa(ci.Block().Index)))
	h.Write([]byte(ci.Common().Signature().String()))
	return fmt.Sprintf("%x", h.Sum64())
}
