package serializer

import (
	"fmt"
	"os"
	"rta"
	"testing"
	"time"

	"golang.org/x/tools/go/ssa"
)

func TestIncrementalRTA(t *testing.T) {
	tests := []struct {
		name      string
		srcBefore string
		srcAfter  string
	}{
		{
			name:      "simple",
			srcBefore: "../tests/simple/before.go",
			srcAfter:  "../tests/simple/after.go",
		},
		{
			name:      "deletion",
			srcBefore: "../tests/deletion/before.go",
			srcAfter:  "../tests/deletion/after.go",
		},
		{
			name:      "fnptr",
			srcBefore: "../tests/fnptr/before.go",
			srcAfter:  "../tests/fnptr/after.go",
		},
		{
			name:      "closures",
			srcBefore: "../tests/closures/before.go",
			srcAfter:  "../tests/closures/after.go",
		},
		{
			name:      "recursion",
			srcBefore: "../tests/recursion/before.go",
			srcAfter:  "../tests/recursion/after.go",
		},
		{
			name:      "mutual_recursion",
			srcBefore: "../tests/mutual_recursion/before.go",
			srcAfter:  "../tests/mutual_recursion/after.go",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

			t.Logf("Before: %d reachable functions", len(resultBefore.Result.Reachable))
			t.Logf("Before: %d call graph nodes", len(resultBefore.Result.CallGraph.Nodes))

			beforeDOT := callGraphToDOT(resultBefore.Result.CallGraph)
			t.Logf("Before call graph:\n%s", beforeDOT)

			// Serialize the "before" result
			ser := NewSerializer()
			pbResult := ser.SerializeRTAResult(resultBefore.Result)
			pbState := ser.SerializeRTAState(resultBefore.State)

			// Load the "after" program
			progAfter, mainPkgAfter, err := LoadTestProgram(tt.srcAfter)
			if err != nil {
				t.Fatalf("failed to load after program: %v", err)
			}

			// Deserialize into the "after" program's context
			startDeserialize := time.Now()
			deser := NewDeserializer(progAfter)
			deserializedResult := deser.DeserializeRTAResult(pbResult)
			deserializedState := deser.DeserializeRTAState(pbState)
			deserializeDuration := time.Since(startDeserialize)

			if deserializedResult == nil || deserializedState == nil {
				t.Fatal("deserialization failed")
			}

			t.Logf("Deserialization took: %v", deserializeDuration)

			// Create ResultWithState for incremental analysis
			beforeStateInAfterContext := &rta.ResultWithState{
				Result: deserializedResult,
				State:  deserializedState,
			}

			t.Logf("Deserialized before state: %d reachable functions", len(beforeStateInAfterContext.Result.Reachable))
			t.Logf("Deserialized before state: %d call graph nodes", len(beforeStateInAfterContext.Result.CallGraph.Nodes))

			// Run full RTA on the "after" program (for comparison)
			mainFuncAfter := mainPkgAfter.Func("main")
			if mainFuncAfter == nil {
				t.Fatal("main function not found in after program")
			}

			startFull := time.Now()
			resultAfterFull := rta.Analyze([]*ssa.Function{mainFuncAfter}, true)
			fullRTADuration := time.Since(startFull)
			if resultAfterFull == nil {
				t.Fatal("full RTA analysis on after program returned nil")
			}

			t.Logf("️Full RTA took: %v", fullRTADuration)

			t.Logf("After (full RTA): %d reachable functions", len(resultAfterFull.Reachable))
			t.Logf("After (full RTA): %d call graph nodes", len(resultAfterFull.CallGraph.Nodes))

			afterFullDOT := callGraphToDOT(resultAfterFull.CallGraph)
			// t.Logf("After (full RTA) call graph:\n%s", afterFullDOT)

			diffs := deser.Diff

			// Run incremental RTA with the changed function
			startIncremental := time.Now()
			resultAfterIncremental := rta.IncrementalAnalyze(diffs.ModifiedFunctions, beforeStateInAfterContext)
			incrementalRTADuration := time.Since(startIncremental)
			if resultAfterIncremental == nil {
				t.Fatal("incremental RTA analysis returned nil")
			}

			t.Logf("Incremental RTA took: %v", incrementalRTADuration)
			t.Logf("Speedup: %.2fx (Full: %v, Incremental: %v)",
				float64(fullRTADuration)/float64(incrementalRTADuration),
				fullRTADuration, incrementalRTADuration)

			t.Logf("After (incremental): %d reachable functions", len(resultAfterIncremental.Result.Reachable))
			t.Logf("After (incremental): %d call graph nodes", len(resultAfterIncremental.Result.CallGraph.Nodes))

			afterIncrementalDOT := callGraphToDOT(resultAfterIncremental.Result.CallGraph)
			// t.Logf("After (incremental) call graph:\n%s", afterIncrementalDOT)

			// Compare full RTA and incremental RTA results
			if afterFullDOT != afterIncrementalDOT {
				// Save DOT files for inspection
				t.Logf("Writing full RTA call graph to full_rta_%s.dot", tt.name)
				os.WriteFile(fmt.Sprintf("full_rta_%s.dot", tt.name), []byte(afterFullDOT), 0644)
				t.Logf("Writing incremental RTA call graph to incremental_rta_%s.dot", tt.name)
				os.WriteFile(fmt.Sprintf("incremental_rta_%s.dot", tt.name), []byte(afterIncrementalDOT), 0644)
				t.Errorf("Call graphs don't match!\nFull RTA:\n%s\nIncremental RTA:\n%s",
					afterFullDOT, afterIncrementalDOT)
			}

			// Ensure reachable functions match
			if len(resultAfterFull.Reachable) != len(resultAfterIncremental.Result.Reachable) {
				t.Errorf("Number of reachable functions don't match! Full RTA: %d, Incremental RTA: %d",
					len(resultAfterFull.Reachable), len(resultAfterIncremental.Result.Reachable))
			}

			for fn := range resultAfterFull.Reachable {
				if _, ok := resultAfterIncremental.Result.Reachable[fn]; !ok {
					t.Errorf("Function %s reachable in full RTA but not in incremental RTA", fn.String())
				}
			}

			t.Log("Incremental RTA test passed - results match full RTA")
		})
	}
}
