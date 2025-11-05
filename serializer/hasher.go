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

	h := fnv.New64a()

	// Hash function identity
	h.Write([]byte(f.String()))

	// Hash function signature
	if f.Signature != nil {
		h.Write([]byte(f.Signature.String()))
	}

	// Hash function body (instructions)
	for _, block := range f.Blocks {
		h.Write([]byte(fmt.Sprintf("block:%d", block.Index)))
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

// This is just a fun function that seems useful to get the Type from a string
// func parseTypeString(typeStr string, prog *ssa.Program) types.Type {
// 	// Parse the type expression
// 	tv, err := types.Eval(token.NewFileSet(), prog.Package(prog.ImportedPackage("builtin").Pkg).Pkg, token.NoPos, typeStr)
// 	if err != nil {
// 		return nil
// 	}
// 	return tv.Type
// }
