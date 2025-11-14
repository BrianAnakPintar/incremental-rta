package serializer

import (
	"fmt"
	"go/types"
	"rta"
	pb "rta/proto/generated"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
	"golang.org/x/tools/go/types/typeutil"
)

type Deserializer struct {
	prog     *ssa.Program
	packages map[string]*ssa.Package

	// fields for faster lookup :)
	functions map[string]*ssa.Function       // We will use function hash as key
	callSites map[string]ssa.CallInstruction // We will use call site hash as key
	nodes     map[string]*callgraph.Node
	edges     map[string]*callgraph.Edge
	// map of type string -> types.Type discovered in the program
	typesMap map[string]types.Type

	Diff *Diff
}

type Diff struct {
	ModifiedFunctions []*ssa.Function
	RemovedFunctions  []*pb.Function // Stored as pb.Function since they may not exist in the current prog
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
		edges:     make(map[string]*callgraph.Edge),
		typesMap:  make(map[string]types.Type),
		Diff: &Diff{
			ModifiedFunctions: make([]*ssa.Function, 0),
			RemovedFunctions:  make([]*pb.Function, 0),
		},
	}
	return res
}

/*
This one is stupid. Because I think it has the same runtime as running RTA again.
*/
func (d *Deserializer) deserializeAllFunctions() {
	visitedTypes := make(map[string]bool) // Use string representation to avoid issues with type identity

	// First, collect all types from package members
	for _, pkg := range d.prog.AllPackages() {
		for _, member := range pkg.Members {
			if t, ok := member.(*ssa.Type); ok {
				d.exploreTypeRecursively(t.Type(), visitedTypes)
			}
		}
	}

	// Also collect types from all functions' signatures and instructions,
	// including functions with pkg=nil (like generated/synthetic functions)
	fns := ssautil.AllFunctions(d.prog)
	for fn := range fns {
		hash := hashFunction(fn)
		d.functions[hash] = fn
		d.collectTypesFromFunction(fn, visitedTypes)
	}

}

// collectTypesFromFunction extracts types from a function and its instructions
func (d *Deserializer) collectTypesFromFunction(fn *ssa.Function, visitedTypes map[string]bool) {
	// Add types from function signature
	if fn.Signature != nil {
		if fn.Signature.Params() != nil {
			for i := 0; i < fn.Signature.Params().Len(); i++ {
				d.exploreTypeRecursively(fn.Signature.Params().At(i).Type(), visitedTypes)
			}
		}
		if fn.Signature.Results() != nil {
			for i := 0; i < fn.Signature.Results().Len(); i++ {
				d.exploreTypeRecursively(fn.Signature.Results().At(i).Type(), visitedTypes)
			}
		}
	}

	// Add types from function body instructions
	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			// Add the type of the instruction's result
			if v, ok := instr.(ssa.Value); ok {
				d.exploreTypeRecursively(v.Type(), visitedTypes)
			}

			// Add types from operands
			var space [8]*ssa.Value
			for _, op := range instr.Operands(space[:0]) {
				if *op != nil {
					d.exploreTypeRecursively((*op).Type(), visitedTypes)
				}
			}
		}
	}
}

// exploreTypeRecursively explores a type and all its embedded/field types,
// adding exported methods for each type encountered
func (d *Deserializer) exploreTypeRecursively(typ types.Type, visitedTypes map[string]bool) {
	if typ == nil {
		return
	}

	// Use string representation as key to avoid type identity issues
	typeStr := typ.String()
	if visitedTypes[typeStr] {
		return
	}
	visitedTypes[typeStr] = true

	// Record the type in the types map for later lookup during deserialization
	if d.typesMap == nil {
		d.typesMap = make(map[string]types.Type)
	}
	d.typesMap[typeStr] = typ

	// Add exported methods for this type
	mset := d.prog.MethodSets.MethodSet(typ)
	for i := 0; i < mset.Len(); i++ {
		sel := mset.At(i)
		m := sel.Obj()
		if m.Exported() {
			methodValue := d.prog.MethodValue(sel)
			if methodValue != nil {
				hash := hashFunction(methodValue)
				d.functions[hash] = methodValue
			}
		}
	}

	// Now recursively explore embedded types
	d.exploreEmbeddedTypesRecursively(typ, visitedTypes)
}

// exploreEmbeddedTypesRecursively recursively explores embedded struct types
// and container element types
func (d *Deserializer) exploreEmbeddedTypesRecursively(typ types.Type, visitedTypes map[string]bool) {
	if typ == nil {
		return
	}

	typ = types.Unalias(typ)

	switch t := typ.(type) {
	case *types.Named:
		// Explore underlying type of named types
		d.exploreTypeRecursively(t.Underlying(), visitedTypes)

	case *types.Pointer:
		// Explore element type of pointers
		d.exploreTypeRecursively(t.Elem(), visitedTypes)

	case *types.Struct:
		// For struct types, explore all field types (including embedded types)
		for i := 0; i < t.NumFields(); i++ {
			field := t.Field(i)
			fieldType := field.Type()
			d.exploreTypeRecursively(fieldType, visitedTypes)
		}

	case *types.Slice:
		d.exploreTypeRecursively(t.Elem(), visitedTypes)

	case *types.Array:
		d.exploreTypeRecursively(t.Elem(), visitedTypes)

	case *types.Map:
		d.exploreTypeRecursively(t.Key(), visitedTypes)
		d.exploreTypeRecursively(t.Elem(), visitedTypes)

	case *types.Chan:
		d.exploreTypeRecursively(t.Elem(), visitedTypes)

	case *types.Signature:
		// Explore parameter and result types
		if t.Params() != nil {
			for i := 0; i < t.Params().Len(); i++ {
				d.exploreTypeRecursively(t.Params().At(i).Type(), visitedTypes)
			}
		}
		if t.Results() != nil {
			for i := 0; i < t.Results().Len(); i++ {
				d.exploreTypeRecursively(t.Results().At(i).Type(), visitedTypes)
			}
		}
	}
}

func (d *Deserializer) deserializeFunction(f *pb.Function) *ssa.Function {
	if f == nil {
		panic("function is nil, should not happen ever")
	}

	if existing, ok := d.functions[f.Hash]; ok {
		return existing
	}

	var pkg *ssa.Package
	pkg, ok := d.packages[f.Package.Path]
	if !ok {
		pkg = d.prog.Package(d.prog.ImportedPackage(f.Package.Path).Pkg)
		d.packages[f.Package.Path] = pkg
	}

	fn := pkg.Func(f.Name)
	d.functions[f.Hash] = fn

	if fn == nil {
		// Function no longer exists, mark as removed
		d.Diff.RemovedFunctions = append(d.Diff.RemovedFunctions, f)
	} else {
		// Function exists, mark as modified
		d.Diff.ModifiedFunctions = append(d.Diff.ModifiedFunctions, fn)
	}

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
	if e == nil || e.Caller == nil || e.Callee == nil {
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

	siteHash := ""
	if e.Site != nil {
		siteHash = e.Site.Hash
	}
	key := fmt.Sprintf("%s-%s-%s", e.Caller.Hash, siteHash, e.Callee.Hash)
	if existing, ok := d.edges[key]; ok {
		return existing
	}

	edge := &callgraph.Edge{Caller: callerNd, Callee: calleeNd, Site: site}
	d.edges[key] = edge
	return edge
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

	res := &rta.Result{
		CallGraph: cg,
		Reachable: reachable,
	}

	// Reconstruct runtime types map
	hasher := typeutil.MakeHasher()
	res.RuntimeTypes.SetHasher(hasher)
	for typeStr, skip := range pbRTAResult.RuntimeTypes {
		if T, ok := d.typesMap[typeStr]; ok {
			res.RuntimeTypes.Set(T, skip)
		}
	}

	return res
}

func (d *Deserializer) DeserializeRTAState(pbRTAState *pb.RTAState) *rta.RTAState {
	if pbRTAState == nil {
		return nil
	}

	rtaState := &rta.RTAState{
		Summary: make(map[*ssa.Function]*rta.MethodSummary),
	}

	if pbRTAState.ReflectValueCall != nil {
		rtaState.ReflectValueCall = d.deserializeFunction(pbRTAState.ReflectValueCall)
	}

	// Deserialize AddrTakenFuncsBySig
	// The serializer stores the signature as a string, but we need to reconstruct
	// the types.Type key and store map[*ssa.Function]bool as the value
	for _, pbListOfFuncs := range pbRTAState.AddrTakenFuncsBySig {
		funcMap := make(map[*ssa.Function]bool)
		var sigType types.Type

		for _, pbFn := range pbListOfFuncs.Functions {
			fn := d.deserializeFunction(pbFn)
			if fn != nil {
				funcMap[fn] = true
				// Use the signature from the first valid function
				if sigType == nil && fn.Signature != nil {
					sigType = fn.Signature
				}
			}
		}

		// Only add if we found a valid signature type
		if sigType != nil && len(funcMap) > 0 {
			rtaState.AddrTakenFuncsBySig.Set(sigType, funcMap)
		}
	}

	// Deserialize DynCallSites
	// Similar approach: reconstruct types.Type from the signature string
	for _, pbListOfCallSites := range pbRTAState.DynCallSites {
		callSites := make([]ssa.CallInstruction, 0, len(pbListOfCallSites.CallSites))
		var sigType types.Type

		for _, pbCS := range pbListOfCallSites.CallSites {
			cs := d.deserializeCallSite(pbCS)
			if cs != nil {
				callSites = append(callSites, cs)
				// Use the signature from the first valid call site
				if sigType == nil && cs.Common().Signature() != nil {
					sigType = cs.Common().Signature()
				}
			}
		}

		// Only add if we found a valid signature type
		if sigType != nil && len(callSites) > 0 {
			rtaState.DynCallSites.Set(sigType, callSites)
		}
	}

	// Deserialize InvokeSites (interface call sites)
	for _, pbListOfCallSites := range pbRTAState.InvokeSites {
		callSites := make([]ssa.CallInstruction, 0, len(pbListOfCallSites.CallSites))
		var sigType types.Type

		for _, pbCS := range pbListOfCallSites.CallSites {
			cs := d.deserializeCallSite(pbCS)
			if cs != nil {
				callSites = append(callSites, cs)
				// Use the interface type from the first valid call site
				if sigType == nil {
					// For invoke sites, the value.Type() is an interface
					if cs.Common().Value != nil {
						t := cs.Common().Value.Type()
						if t != nil {
							sigType = t
						}
					}
				}
			}
		}

		if sigType != nil && len(callSites) > 0 {
			rtaState.InvokeSites.Set(sigType, callSites)
		}
	}

	// Deserialize method summaries
	if pbRTAState.Summary != nil {
		for fnHash, pbSummary := range pbRTAState.Summary {
			fn := d.functions[fnHash]
			if fn == nil {
				continue
			}
			summary := &rta.MethodSummary{
				Provenance:       make([]*ssa.Function, 0, len(pbSummary.Provenance)),
				FunctionsCreated: make([]*ssa.Function, 0, len(pbSummary.FunctionsCreated)),
			}

			// Deserialize provenance
			for _, pbProvFn := range pbSummary.Provenance {
				provFn := d.deserializeFunction(pbProvFn)
				if provFn != nil {
					summary.Provenance = append(summary.Provenance, provFn)
				}
			}

			// Deserialize functions created
			for _, pbCreatedFn := range pbSummary.FunctionsCreated {
				createdFn := d.deserializeFunction(pbCreatedFn)
				if createdFn != nil {
					summary.FunctionsCreated = append(summary.FunctionsCreated, createdFn)
				}
			}

			rtaState.Summary[fn] = summary
		}
	}

	// Deserialize roots
	if len(pbRTAState.Roots) > 0 {
		rtaState.Roots = make([]*ssa.Function, 0, len(pbRTAState.Roots))
		for _, pbRoot := range pbRTAState.Roots {
			rootFn := d.deserializeFunction(pbRoot)
			if rootFn != nil {
				rtaState.Roots = append(rtaState.Roots, rootFn)
			}
		}
	}

	return rtaState
}

// === End RTA deserialization ===
