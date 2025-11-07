package serializer

import (
	"rta"
	pb "rta/proto/generated"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

// The struct provides faster lookup and is helpful for dealing with addresses
type Serializer struct {
	functions map[*ssa.Function]*pb.Function
	callsites map[ssa.CallInstruction]*pb.CallSite
	nodes     map[*callgraph.Node]*pb.Node
}

func NewSerializer() *Serializer {
	return &Serializer{
		functions: make(map[*ssa.Function]*pb.Function),
		callsites: make(map[ssa.CallInstruction]*pb.CallSite),
		nodes:     make(map[*callgraph.Node]*pb.Node),
	}
}

// === ssa serialization ===

func (s *Serializer) serializeFunction(f *ssa.Function) *pb.Function {
	if f == nil {
		panic("Something went wrong. Trying to serialize a nil function")
	}

	if existing, ok := s.functions[f]; ok {
		return existing
	}

	var res *pb.Function

	var pkg *pb.Package
	if f.Pkg != nil && f.Pkg.Pkg != nil {
		pkg = &pb.Package{
			Name: f.Pkg.Pkg.Name(),
			Path: f.Pkg.Pkg.Path(),
		}
	}

	if f.Pkg == nil || f.Pkg.Pkg == nil {
		res = &pb.Function{
			Name:      f.Name(),
			Package:   &pb.Package{Name: "unknown", Path: "unknown"}, // TODO: leave for now
			Signature: f.Signature.String(),
			Hash:      hashFunction(f),
		}
		s.functions[f] = res
		return res
	}

	res = &pb.Function{
		Name:      f.Name(),
		Package:   pkg,
		Signature: f.Signature.String(),
		Hash:      hashFunction(f),
	}

	s.functions[f] = res
	return res
}

func (s *Serializer) serializeCallSite(ci ssa.CallInstruction) *pb.CallSite {
	if ci == nil {
		// There are some cases where the callsite is nil, I don't understand why yet.
		// GPT says:
		/*
			A nil callsite means:
			“This edge exists logically in the callgraph, but there’s no specific SSA
			instruction in the source program that caused it.”
			For your particular case with (reflect.Value).Call → runtime.getempty$1,
			it’s expected and comes from compiler/runtime stubs used to implement reflection.
			Totally normal — you shouldn’t try to “fix” or filter it out unless you’re intentionally
			pruning runtime internals.
		*/
		return nil
	}

	if existing, ok := s.callsites[ci]; ok {
		return existing
	}

	res := &pb.CallSite{
		Hash:           hashCallSite(ci),
		ParentFunction: s.serializeFunction(ci.Parent()),
		Signature:      ci.Common().Signature().String(),
		BlockIndex:     int32(ci.Block().Index),
	}

	s.callsites[ci] = res
	return res
}

// === End ssa serialization ===

// === Graph serialization ===

func (s *Serializer) serializeEdge(e *callgraph.Edge) *pb.Edge {
	if e == nil {
		panic("Something went wrong. Trying to serialize a nil edge")
	}
	return &pb.Edge{
		Caller: s.serializeFunction(e.Caller.Func),
		Site:   s.serializeCallSite(e.Site),
		Callee: s.serializeFunction(e.Callee.Func),
	}
}

func (s *Serializer) serializeNode(n *callgraph.Node) *pb.Node {
	if existing, ok := s.nodes[n]; ok {
		return existing
	}

	if n.Func == nil {
		panic("Serializing node went kaboom, func is nil")
	}

	pbNode := &pb.Node{
		Function: s.serializeFunction(n.Func),
		In:       make([]*pb.Edge, 0, len(n.In)),
		Out:      make([]*pb.Edge, 0, len(n.Out)),
	}

	s.nodes[n] = pbNode

	for _, inEdge := range n.In {
		pbEdge := s.serializeEdge(inEdge)
		if pbEdge != nil {
			pbNode.In = append(pbNode.In, pbEdge)
		}
	}

	for _, outEdge := range n.Out {
		pbEdge := s.serializeEdge(outEdge)
		if pbEdge != nil {
			pbNode.Out = append(pbNode.Out, pbEdge)
		}
	}

	return pbNode
}

func (s *Serializer) serializeCallGraph(cg *callgraph.Graph) *pb.CallGraph {
	pbCG := &pb.CallGraph{
		Root:  s.serializeNode(cg.Root),
		Nodes: make([]*pb.Node, 0, len(cg.Nodes)),
	}

	for _, node := range cg.Nodes {
		pbNode := s.serializeNode(node)
		if pbNode != nil {
			pbCG.Nodes = append(pbCG.Nodes, pbNode)
		}
	}

	return pbCG
}

// === End graph serialization ===

// === RTA serialization ===
func (s *Serializer) SerializeRTAResult(rtaResult *rta.Result) *pb.RTAResult {
	pbRTAResult := &pb.RTAResult{
		CallGraph: s.serializeCallGraph(rtaResult.CallGraph),
		Reachable: make([]*pb.ReachableEntry, 0, len(rtaResult.Reachable)),
	}

	for fn, addrTaken := range rtaResult.Reachable {
		pbFn := s.serializeFunction(fn)
		pbRTAResult.Reachable = append(pbRTAResult.Reachable, &pb.ReachableEntry{
			Function:     pbFn,
			AddressTaken: addrTaken.AddrTaken,
		})
	}

	return pbRTAResult
}

func (s *Serializer) SerializeRTAState(rtaState *rta.RTAState) *pb.RTAState {
	pbRTAState := &pb.RTAState{
		AddrTakenFuncsBySig: make(map[string]*pb.ListOfFunctions),
		DynCallSites:        make(map[string]*pb.ListOfCallSites),
	}

	// Only serialize ReflectValueCall if it's not nil
	if rtaState.ReflectValueCall != nil {
		pbRTAState.ReflectValueCall = s.serializeFunction(rtaState.ReflectValueCall)
	}

	for _, sig := range rtaState.AddrTakenFuncsBySig.Keys() {
		funcMap := rtaState.AddrTakenFuncsBySig.At(sig).(map[*ssa.Function]bool)
		funcs := make([]*ssa.Function, 0, len(funcMap))
		for fn := range funcMap {
			funcs = append(funcs, fn)
		}
		pbFuncs := make([]*pb.Function, 0, len(funcs))
		for _, fn := range funcs {
			pbFuncs = append(pbFuncs, s.serializeFunction(fn))
		}

		pbRTAState.AddrTakenFuncsBySig[sig.String()] = &pb.ListOfFunctions{Functions: pbFuncs}
	}

	for _, sig := range rtaState.DynCallSites.Keys() {
		sites := rtaState.DynCallSites.At(sig).([]ssa.CallInstruction)
		pbSites := make([]*pb.CallSite, 0, len(sites))
		for _, site := range sites {
			pbSites = append(pbSites, s.serializeCallSite(site))
		}

		pbRTAState.DynCallSites[sig.String()] = &pb.ListOfCallSites{CallSites: pbSites}
	}

	for fn, summary := range rtaState.Summary {
		if pbRTAState.Summary == nil {
			pbRTAState.Summary = make(map[string]*pb.MethodSummary)
		}
		pbRTAState.Summary[hashFunction(fn)] = s.SerializeRTAMethodSummaries(map[*ssa.Function]*rta.MethodSummary{fn: summary})[hashFunction(fn)]
	}

	return pbRTAState
}

func (s *Serializer) SerializeRTAMethodSummaries(summaries map[*ssa.Function]*rta.MethodSummary) map[string]*pb.MethodSummary {
	pbSummaries := make(map[string]*pb.MethodSummary)

	for fn, summary := range summaries {
		pbProvenance := make([]*pb.Function, 0, len(summary.Provenance))
		for _, provFn := range summary.Provenance {
			pbProvenance = append(pbProvenance, s.serializeFunction(provFn))
		}

		pbFuncsCreated := make([]*pb.Function, 0, len(summary.FunctionsCreated))
		for _, createdFn := range summary.FunctionsCreated {
			pbFuncsCreated = append(pbFuncsCreated, s.serializeFunction(createdFn))
		}

		pbSummaries[hashFunction(fn)] = &pb.MethodSummary{
			Provenance:       pbProvenance,
			FunctionsCreated: pbFuncsCreated,
		}
	}

	return pbSummaries
}

// === End RTA serialization ===
