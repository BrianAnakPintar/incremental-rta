package serializer

import (
	"fmt"
	"go/types"
	"log"
	"rta"
	pb "rta/proto/generated"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

type Deserializer struct {
	prog     *ssa.Program
	packages map[string]*ssa.Package

	// fields for faster lookup :)
	functions map[string]*ssa.Function       // We will use function hash as key
	callSites map[string]ssa.CallInstruction // We will use call site hash as key
	nodes     map[string]*callgraph.Node
}

func NewDeserializer(prog *ssa.Program) *Deserializer {
	packages := make(map[string]*ssa.Package)
	for _, pkg := range prog.AllPackages() {
		packages[pkg.Pkg.Path()] = pkg
	}
	res := &Deserializer{
		prog:      prog,
		packages:  packages,
		functions: make(map[string]*ssa.Function),
		callSites: make(map[string]ssa.CallInstruction),
		nodes:     make(map[string]*callgraph.Node),
	}
	return res
}

/*
This one is stupid. Because I think it has the same runtime as running RTA again.
*/
func (d *Deserializer) deserializeAllFunctions() {

	d.functions = BuildDefinitiveFunctionMap(d.prog)
	fns := ssautil.AllFunctions(d.prog)
	for fn := range fns {
		hash := hashFunction(fn)
		d.functions[hash] = fn
	}
}

func (d *Deserializer) deserializeFunction(f *pb.Function) *ssa.Function {
	if f == nil {
		panic("function is nil, should not happen ever")
	}

	if existing, ok := d.functions[f.Hash]; ok {
		return existing
	}

	if f.Package == nil {
		fmt.Printf("%v\n", f.Hash)
		// Temporary solution
		tmpSig := types.NewSignature(nil, nil, nil, false)
		tmp := d.prog.NewFunction(f.Name, tmpSig, "deserializer-bad-code")
		d.functions[f.Hash] = tmp
		return tmp
	}

	pkg, ok := d.packages[f.Package.Path]
	if !ok {
		pkg = d.prog.Package(d.prog.ImportedPackage(f.Package.Path).Pkg)
		d.packages[f.Package.Path] = pkg
	}

	fn := pkg.Func(f.Name)
	d.functions[f.Hash] = fn
	return fn
}

func (d *Deserializer) deserializeCallSite(cs *pb.CallSite) ssa.CallInstruction {
	if cs == nil {
		return nil
	}
	if existing, ok := d.callSites[cs.Hash]; ok {
		return existing
	}
	parentFunc := d.deserializeFunction(cs.ParentFunction)
	if parentFunc == nil {
		// Most likely the original fn is deleted
		return nil
	}

	for _, block := range parentFunc.Blocks {
		for _, instr := range block.Instrs {
			ci, ok := instr.(ssa.CallInstruction)
			if !ok {
				continue
			}
			if hashCallSite(ci) == cs.Hash {
				d.callSites[cs.Hash] = ci
				return ci
			}
		}
	}

	// Throw nil, most likely caused by a change in the original function
	return nil
}

// === Callgraph deserialization ===

func (d *Deserializer) deserializeEdge(e *pb.Edge) *callgraph.Edge {
	if e == nil {
		return nil
	}
	site := d.deserializeCallSite(e.Site)

	// Get the callgraph nodes
	callerNd, ok := d.nodes[e.Caller.Hash]
	if !ok {
		// most likely the original function is deleted
		return nil
	}
	calleeNd, ok := d.nodes[e.Callee.Hash]
	if !ok {
		// most likely the original function is deleted
		return nil
	}

	return &callgraph.Edge{Caller: callerNd, Callee: calleeNd, Site: site}
}

func (d *Deserializer) deserializeNodeOnly(n *pb.Node) *callgraph.Node {
	if n == nil || n.Function == nil {
		return nil
	}

	fn := d.deserializeFunction(n.Function)
	if fn == nil {
		return nil
	}

	// use function hash as node key
	key := n.Function.Hash
	if existing, ok := d.nodes[key]; ok {
		return existing
	}

	cgNode := &callgraph.Node{
		Func: fn,
		In:   make([]*callgraph.Edge, 0, len(n.In)),
		Out:  make([]*callgraph.Edge, 0, len(n.Out)),
	}

	d.nodes[key] = cgNode
	return cgNode
}

func (d *Deserializer) DeserializeCallGraph(pbCG *pb.CallGraph) *callgraph.Graph {
	if pbCG == nil {
		return nil
	}

	// ensure root is deserialized first
	root := d.deserializeNodeOnly(pbCG.Root)

	// callgraph.Graph.Nodes is a map[*ssa.Function]*callgraph.Node
	nodes := make(map[*ssa.Function]*callgraph.Node)

	/*
		We must first deserialize all nodes so that edges can reference them.
		Then we can populate the edges.
	*/
	for _, n := range pbCG.Nodes {
		nd := d.deserializeNodeOnly(n)
		if nd != nil && nd.Func != nil {
			nodes[nd.Func] = nd
		}
	}

	for _, n := range pbCG.Nodes {
		nd, ok := d.nodes[n.Function.Hash]
		if !ok {
			continue
		}

		// populate in-edges
		for _, inEdgePB := range n.In {
			inEdge := d.deserializeEdge(inEdgePB)
			if inEdge != nil {
				nd.In = append(nd.In, inEdge)
			}
		}

		// populate out-edges
		for _, outEdgePB := range n.Out {
			outEdge := d.deserializeEdge(outEdgePB)
			if outEdge != nil {
				nd.Out = append(nd.Out, outEdge)
			}
		}
	}

	return &callgraph.Graph{Root: root, Nodes: nodes}
}

// === End Callgraph deserialization ===

// === RTA deserialization ===
func (d *Deserializer) DeserializeRTAResult(pbRTAResult *pb.RTAResult) *rta.Result {
	if pbRTAResult == nil {
		return nil
	}

	fmt.Printf("There are %d functions\n", len(pbRTAResult.Reachable))

	// Inefficient but my duct tape solution for lambdas and package-less functions
	d.deserializeAllFunctions()

	cg := d.DeserializeCallGraph(pbRTAResult.CallGraph)
	reachable := make(map[*ssa.Function]struct{ AddrTaken bool })

	for _, reachableEntry := range pbRTAResult.Reachable {
		fn := d.deserializeFunction(reachableEntry.Function)
		if fn != nil {
			reachable[fn] = struct{ AddrTaken bool }{AddrTaken: reachableEntry.AddressTaken}
		}
	}

	return &rta.Result{
		CallGraph: cg,
		Reachable: reachable,
	}
}

// === End RTA deserialization ===

func BuildDefinitiveFunctionMap(prog *ssa.Program) map[string]*ssa.Function {
	lookup := make(map[string]*ssa.Function)
	queue := make([]*ssa.Function, 0) // A queue for finding nested closures

	// Helper to add a function to the map and queue if it's new
	add := func(fn *ssa.Function) {
		if fn == nil {
			return
		}
		// Use fn.String() as the unique, serializable key
		if _, exists := lookup[hashFunction(fn)]; !exists {
			lookup[hashFunction(fn)] = fn
			queue = append(queue, fn) // Add to queue to scan for anon funcs
		}
	}

	// Helper to get all methods/thunks for a given type
	methodsOf := func(T types.Type) {
		if types.IsInterface(T) {
			return // Interfaces don't have concrete methods
		}
		mset := prog.MethodSets.MethodSet(T)
		for i := 0; i < mset.Len(); i++ {
			// This is the public API to get a method/thunk *ssa.Function.
			// This is what RTA uses and is what populates the
			// unexported 'objectMethods' cache.
			add(prog.MethodValue(mset.At(i)))
		}
	}

	// === Step 1: Get all package-level functions ===
	// This finds 'main.main', 'init', 'fmt.Println', etc.
	for _, pkg := range prog.AllPackages() {
		if pkg == nil {
			continue
		}
		for _, member := range pkg.Members {
			if fn, ok := member.(*ssa.Function); ok {
				add(fn)
			}
		}
	}

	// === Step 2: Get all methods/thunks for Runtime Types ===
	// This is the CRITICAL step for finding your missing functions.
	// prog.RuntimeTypes() returns all concrete types (incl. anonymous structs)
	// that were used in a MakeInterface instruction.
	for _, T := range prog.RuntimeTypes() {
		methodsOf(T)                   // Finds methods on T
		methodsOf(types.NewPointer(T)) // Finds methods on *T
	}

	// === Step 3: Recursively find all anonymous closures ===
	// Process the queue, which now contains all functions from steps 1 & 2.
	// We scan their 'AnonFuncs' field to find all nested closures.
	for i := 0; i < len(queue); i++ { // Use a queue, not recursion
		fn := queue[i]
		for _, anonFn := range fn.AnonFuncs {
			add(anonFn) // add() handles duplicates and enqueues new funcs
		}
	}

	log.Printf("Built definitive map with %d total functions.", len(lookup))
	return lookup
}
