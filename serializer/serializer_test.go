package serializer

import (
	"bytes"
	"fmt"
	"go/token"
	"log"
	"os"
	"rta"
	"sort"
	"testing"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

/*
	Tests for serializing and deserializing our stuff.
*/

func callGraphToDOT(cg *callgraph.Graph) string {
	type edge struct {
		caller, callee string
	}
	var edges []edge
	for _, node := range cg.Nodes {
		for _, out := range node.Out {
			caller := out.Caller.Func.String()
			callee := out.Callee.Func.String()
			edges = append(edges, edge{caller, callee})
		}
	}
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].caller != edges[j].caller {
			return edges[i].caller < edges[j].caller
		}
		return edges[i].callee < edges[j].callee
	})
	var buf bytes.Buffer
	buf.WriteString("digraph {\n")
	for _, e := range edges {
		buf.WriteString(fmt.Sprintf("  \"%s\" -> \"%s\";\n", e.caller, e.callee))
	}
	buf.WriteString("}\n")
	return buf.String()
}

// TestSerializeRTA runs RTA on a tiny temporary program, serializes the
// RTA result, then deserializes it and performs basic sanity checks.
func TestSerializeRTA(t *testing.T) {
	// Load the test program
	prog, mainPkg, err := LoadTestProgram("testdata/main.go")
	if err != nil {
		t.Fatalf("failed to load test program: %v", err)
	}

	mainFn := mainPkg.Func("main")

	rtaResult := rta.Analyze([]*ssa.Function{mainFn}, true)

	oldCG := callGraphToDOT(rtaResult.CallGraph)

	serializer := NewSerializer()
	pbRTAResult := serializer.SerializeRTAResult(rtaResult)

	// Now let's try to deserialize it and see if it looks right
	deserializer := NewDeserializer(prog)
	res := deserializer.DeserializeRTAResult(pbRTAResult)

	myStr := callGraphToDOT(res.CallGraph)

	// Write both as file
	os.WriteFile("old_call_graph.dot", []byte(oldCG), 0644)
	os.WriteFile("new_call_graph.dot", []byte(myStr), 0644)

	if oldCG != myStr {
		t.Errorf("deserialized call graph does not match original")
	}
}

// Loads a Go program located at the given path and returns its SSA program and main package.
// REQUIRES: The Test program must have a main package.
func LoadTestProgram(path string) (*ssa.Program, *ssa.Package, error) {
	cfg := &packages.Config{
		Mode: packages.LoadAllSyntax,
		Fset: token.NewFileSet(),
	}
	pkgs, err := packages.Load(cfg, path)
	if err != nil {
		return nil, nil, err
	}

	mode := ssa.InstantiateGenerics
	prog, pkgsSSA := ssautil.AllPackages(pkgs, mode)
	prog.Build()

	var mainPkg *ssa.Package
	for _, p := range pkgsSSA {
		if p.Pkg.Name() == "main" {
			mainPkg = p
			break
		}
	}
	if mainPkg == nil {
		log.Fatalf("no main package found")
	}

	return prog, mainPkg, nil
}

func TestSeparatePrograms(t *testing.T) {
	// Load the test program
	_, mainPkg, err := LoadTestProgram("testdata/main.go")
	if err != nil {
		t.Fatalf("failed to load test program: %v", err)
	}
	new_prog, _, err := LoadTestProgram("testdata/same_main.go")
	if err != nil {
		t.Fatalf("failed to load test program: %v", err)
	}

	mainFn := mainPkg.Func("main")
	rtaResult := rta.Analyze([]*ssa.Function{mainFn}, true)
	oldCG := callGraphToDOT(rtaResult.CallGraph)
	serializer := NewSerializer()
	pbRTAResult := serializer.SerializeRTAResult(rtaResult)

	deserializer := NewDeserializer(new_prog)
	res := deserializer.DeserializeRTAResult(pbRTAResult)

	myStr := callGraphToDOT(res.CallGraph)

	// Write both as file
	os.WriteFile("old_call_graph.dot", []byte(oldCG), 0644)
	os.WriteFile("new_call_graph.dot", []byte(myStr), 0644)

	if oldCG != myStr {
		t.Errorf("deserialized call graph does not match original")
	}
}

func TestHashFunction(t *testing.T) {
	// Load the test program
	_, mainPkg, err := LoadTestProgram("testdata/main.go")
	if err != nil {
		t.Fatalf("failed to load test program: %v", err)
	}

	_, mainPkg2, err := LoadTestProgram("testdata/same_main.go")
	if err != nil {
		t.Fatalf("failed to load test program: %v", err)
	}

	mainFn := mainPkg.Func("main")
	mainFn2 := mainPkg2.Func("main")
	hash1 := hashFunction(mainFn)
	hash2 := hashFunction(mainFn2)

	t.Logf("Hash 1: %s", hash1)
	t.Logf("Hash 2: %s", hash2)
}
