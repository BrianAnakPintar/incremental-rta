package serializer

import (
	"rta"
	pb "rta/proto/generated"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
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

func (d *Deserializer) deserializeFunction(f *pb.Function) *ssa.Function {
	if f == nil {
		panic("function is nil, should not happen ever")
	}
	if f.Package == nil {
		// fmt.Printf("Function %v\n", f)
		return nil
	}

	if existing, ok := d.functions[f.Hash]; ok {
		return existing
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
		nd := d.nodes[n.Function.Hash]
		if nd == nil {
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
