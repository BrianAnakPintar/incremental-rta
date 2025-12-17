package serialized_rta_test

import (
	"fmt"
	"go/token"
	"log"
	"os"
	"path/filepath"
	"rta"
	serializedrta "rta/serialized_rta"
	"rta/serializer"
	"testing"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

func TestProtoIncrementalRTA(t *testing.T) {
	tests := []struct {
		name      string
		srcBefore string
		srcAfter  string
	}{
		{
			name:      "simple",
			srcBefore: "tests/simple/before.go",
			srcAfter:  "tests/simple/after.go",
		},
		{
			name:      "deletion",
			srcBefore: "tests/deletion/before.go",
			srcAfter:  "tests/deletion/after.go",
		},
		{
			name:      "fnptr",
			srcBefore: "tests/fnptr/before.go",
			srcAfter:  "tests/fnptr/after.go",
		},
		{
			name:      "closures",
			srcBefore: "tests/closures/before.go",
			srcAfter:  "tests/closures/after.go",
		},
		{
			name:      "recursion",
			srcBefore: "tests/recursion/before.go",
			srcAfter:  "tests/recursion/after.go",
		},
		{
			name:      "mutual_recursion",
			srcBefore: "tests/mutual_recursion/before.go",
			srcAfter:  "tests/mutual_recursion/after.go",
		},
		{
			name:      "interfaces_add",
			srcBefore: "tests/interfaces_add/before.go",
			srcAfter:  "tests/interfaces_add/after.go",
		},
		{
			name:      "slides",
			srcBefore: "tests/repos/before/slides/main.go",
			srcAfter:  "tests/repos/after/slides/main.go",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wd, _ := os.Getwd()
			if filepath.Base(wd) == "serialized_rta" {
				tt.srcBefore = "../" + tt.srcBefore
				tt.srcAfter = "../" + tt.srcAfter
			}

			// Load the "before" program
			_, mainPkgBefore, err := LoadTestProgram(tt.srcBefore)
			if err != nil {
				t.Fatalf("failed to load before program: %v", err)
			}

			// Run initial RTA on the "before" program
			mainFuncBefore := mainPkgBefore.Func("main")
			if mainFuncBefore == nil {
				t.Fatal("main function not found in before program")
			}

			// Perform initial RTA analysis with state
			resultBefore := rta.AnalyzeAndSaveState([]*ssa.Function{mainFuncBefore}, true)
			if resultBefore == nil {
				t.Fatal("initial RTA analysis returned nil")
			}

			// Serialize the "before" result
			ser := serializer.NewSerializer()
			pbResult := ser.SerializeRTAResult(resultBefore.Result)
			pbState := ser.SerializeRTAState(resultBefore.State)

			// Construct the input for IncrementalAnalyze
			prevRun := &serializedrta.SerializedResult{
				CallGraph: pbResult.CallGraph,
				RTAState:  pbState,
			}
			t.Logf("PrevRun Nodes: %d", len(prevRun.CallGraph.Nodes))

			// Load the "after" program
			progAfter, mainPkgAfter, err := LoadTestProgram(tt.srcAfter)
			if err != nil {
				t.Fatalf("failed to load after program: %v", err)
			}

			// --- GET DIFF, Temp Solution to use Deserializer ---
			// Deserialize into the "after" program's context to get diffs
			deser := serializer.NewDeserializer(progAfter)
			// We deserialize the result just to populate the Diff in deser.
			// We don't use the returned result for the analysis input (we use prevRun).
			_ = deser.DeserializeRTAResult(pbResult)

			// Get modified functions (roots)
			roots := deser.Diff.ModifiedFunctions
			// --- END DIFF GETTING ---

			// Run incremental RTA using protobufs
			resultAfterIncremental := serializedrta.IncrementalAnalyze(roots, prevRun)
			if resultAfterIncremental == nil {
				t.Fatal("incremental RTA analysis returned nil")
			}

			// Verify the result
			// We can compare the call graph with a full RTA on "after" program.

			// Run full RTA on the "after" program
			mainFuncAfter := mainPkgAfter.Func("main")
			if mainFuncAfter == nil {
				t.Fatal("main function not found in after program")
			}

			resultAfterFull := rta.Analyze([]*ssa.Function{mainFuncAfter}, true)

			cg1 := resultAfterFull.CallGraph
			cg2 := resultAfterIncremental.CallGraph

			if len(cg1.Nodes) != len(cg2.Nodes) {
				t.Fatalf("call graph node count mismatch: full RTA has %d nodes, incremental RTA has %d nodes", len(cg1.Nodes), len(cg2.Nodes))
			}

			// Further checks can be added here to compare edges, reachable functions, etc.
			fmt.Printf("Test %s passed: both call graphs have %d nodes\n", tt.name, len(cg1.Nodes))
		})
	}
}

// Helpers copied from rta_test.go

func LoadTestProgram(path string) (*ssa.Program, *ssa.Package, error) {
	cfg := &packages.Config{
		Mode: packages.LoadAllSyntax,
		Fset: token.NewFileSet(),
		Dir:  filepath.Dir(path),
	}
	file := filepath.Base(path)
	pkgs, err := packages.Load(cfg, file)
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
