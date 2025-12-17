package serialized_rta

import (
	"go/types"
	pb "rta/proto/generated"
	"rta/serializer"

	"golang.org/x/tools/go/ssa"
)

type SerializedResult struct {
	CallGraph *pb.CallGraph
	RTAState  *pb.RTAState
}

type IncRTA struct {
	result       *SerializedResult
	serializer   *serializer.Serializer
	deserializer *serializer.Deserializer

	nodes    map[string]*pb.Node
	worklist []*ssa.Function
	analyzed map[string]bool

	traversable          map[string]bool
	potentialUnreachable map[string]*pb.Node
	visitedTypes         map[string]bool
}

func IncrementalAnalyze(roots []*ssa.Function, prevRun *SerializedResult) *SerializedResult {
	if len(roots) == 0 {
		return prevRun
	}

	r := &IncRTA{
		result:               prevRun,
		serializer:           serializer.NewSerializer(),
		deserializer:         serializer.NewDeserializer(roots[0].Prog),
		nodes:                make(map[string]*pb.Node),
		analyzed:             make(map[string]bool),
		traversable:          make(map[string]bool),
		potentialUnreachable: make(map[string]*pb.Node),
		visitedTypes:         make(map[string]bool),
	}

	// Initialize visitedTypes from existing ConcreteTypes
	if r.result.RTAState != nil {
		for _, ct := range r.result.RTAState.ConcreteTypes {
			r.visitedTypes[ct] = false // false means "is a runtime type" (not skipped)
		}
	}

	// Initialize RTAState if nil
	if r.result.RTAState == nil {
		r.result.RTAState = &pb.RTAState{
			AddrTakenFuncsBySig: make(map[string]*pb.ListOfFunctions),
			DynCallSites:        make(map[string]*pb.ListOfCallSites),
			InvokeSites:         make(map[string]*pb.ListOfCallSites),
			Summary:             make(map[string]*pb.MethodSummary),
		}
	}

	r.indexExistingNodes()

	// Build map for lookup of named functions by package path and name
	nodesByName := make(map[string]*pb.Node)
	for _, node := range r.nodes {
		if node.Function.Package != nil {
			key := node.Function.Package.Path + "." + node.Function.Name
			nodesByName[key] = node
		}
	}

	// Prune potentially obsolete nodes from previous run
	for _, fn := range roots {
		hash := serializer.HashFunction(fn)
		nd, ok := r.nodes[hash]
		if !ok {
			// Try lookup by name
			if fn.Pkg != nil {
				key := fn.Pkg.Pkg.Path() + "." + fn.Name()
				if oldNode, found := nodesByName[key]; found {
					nd = oldNode
				}
			}
		}

		if nd == nil {
			continue
		}

		r.removeOutgoingEdges(nd)

		// Remove the old node from the nodes map if it is obsolete (hash mismatch)
		if nd.Function.Hash != hash {
			// Migrate incoming edges to the new node
			newNode := r.getNode(fn)
			for _, edge := range nd.In {
				edge.Callee = newNode.Function
				newNode.In = append(newNode.In, edge)
			}
			nd.In = nil

			delete(r.nodes, nd.Function.Hash)
		}

		if summary, ok := r.result.RTAState.Summary[nd.Function.Hash]; ok {
			r.removeFunctionsCreated(nd.Function, summary)
		}
	}

	// Add roots to worklist
	r.worklist = append(r.worklist, roots...)

	// Populate types from roots
	visitedTypes := make(map[string]bool)
	for _, root := range roots {
		r.deserializer.CollectTypesFromFunction(root, visitedTypes)
	}

	for len(r.worklist) > 0 {
		f := r.worklist[len(r.worklist)-1]
		r.worklist = r.worklist[:len(r.worklist)-1]

		hash := serializer.HashFunction(f)
		if r.analyzed[hash] {
			continue
		}
		r.analyzed[hash] = true
		r.visitFunc(f)
	}

	r.pruneUnreachable()

	return prevRun
}

// removeFunctionsCreated removes functions created as per the given summary.
func (r *IncRTA) removeFunctionsCreated(prov *pb.Function, summary *pb.MethodSummary) {
	for _, created := range summary.FunctionsCreated {
		r.removeBasedOnProvenance(prov, created)
	}
}

func (r *IncRTA) removeBasedOnProvenance(prov *pb.Function, fn *pb.Function) {
	summary, ok := r.result.RTAState.Summary[fn.Hash]
	if !ok {
		return
	}

	// Remove prov from summary.Provenance
	newProv := make([]*pb.Function, 0, len(summary.Provenance))
	for _, p := range summary.Provenance {
		if p.Hash != prov.Hash {
			newProv = append(newProv, p)
		}
	}
	summary.Provenance = newProv

	if len(summary.Provenance) == 0 {
		// Remove from AddrTakenFuncsBySig
		if list, ok := r.result.RTAState.AddrTakenFuncsBySig[fn.Signature]; ok {
			newFuncs := make([]*pb.Function, 0, len(list.Functions))
			for _, f := range list.Functions {
				if f.Hash != fn.Hash {
					newFuncs = append(newFuncs, f)
				}
			}
			list.Functions = newFuncs
		}

		// Remove incoming dynamic edges
		if node, ok := r.nodes[fn.Hash]; ok {
			// We need to identify dynamic edges.
			// Check against DynCallSites
			if sites, ok := r.result.RTAState.DynCallSites[fn.Signature]; ok {
				// Create a set of dynamic call site hashes for fast lookup
				dynSiteHashes := make(map[string]bool)
				for _, s := range sites.CallSites {
					dynSiteHashes[s.Hash] = true
				}

				// Filter incoming edges
				edgesToRemove := make([]*pb.Edge, 0)
				for _, edge := range node.In {
					if dynSiteHashes[edge.Site.Hash] {
						edgesToRemove = append(edgesToRemove, edge)
					}
				}

				for _, edge := range edgesToRemove {
					r.removeEdge(edge)
				}
			}

			// If no incoming edges, mark as potentially unreachable
			if len(node.In) == 0 {
				r.potentialUnreachable[fn.Hash] = node
			}
		}
	}
}

func (r *IncRTA) pruneUnreachable() {
	// Mark traversable from roots
	if r.result.CallGraph.Root != nil {
		r.markTraversable(r.result.CallGraph.Root)
	}

	for len(r.potentialUnreachable) > 0 {
		// Pop one
		var hash string
		var node *pb.Node
		for h, n := range r.potentialUnreachable {
			hash = h
			node = n
			break
		}
		delete(r.potentialUnreachable, hash)

		if r.traversable[hash] {
			continue
		}

		// Remove node
		r.removeOutgoingEdges(node)
		delete(r.nodes, hash)

		if summary, ok := r.result.RTAState.Summary[hash]; ok {
			r.removeFunctionsCreated(node.Function, summary)
		}
	}

	// Rebuild CallGraph.Nodes list
	newNodes := make([]*pb.Node, 0, len(r.nodes))
	for _, node := range r.nodes {
		newNodes = append(newNodes, node)
	}
	r.result.CallGraph.Nodes = newNodes
}

func (r *IncRTA) markTraversable(node *pb.Node) {
	if r.traversable[node.Function.Hash] {
		return
	}
	r.traversable[node.Function.Hash] = true
	for _, edge := range node.Out {
		// Ensure callee node exists in our map (it should)
		if calleeNode, ok := r.nodes[edge.Callee.Hash]; ok {
			r.markTraversable(calleeNode)
		}
	}
}

// removeOutgoingEdges removes all outgoing edges from the specified node.
func (r *IncRTA) removeOutgoingEdges(node *pb.Node) {
	for _, edge := range node.Out {
		r.removeEdge(edge)
	}
	if len(node.Out) != 0 {
		panic("Err: removeOutgoingEdges should have 0 remaining out edge")
	}
}

// removeEdge removes the specified edge from the call graph.
func (r *IncRTA) removeEdge(edge *pb.Edge) {
	// Remove from caller's Out edges
	callerNode, ok := r.nodes[edge.Caller.Hash]
	if ok {
		newOut := make([]*pb.Edge, 0, len(callerNode.Out))
		for _, e := range callerNode.Out {
			if e != edge {
				newOut = append(newOut, e)
			}
		}
		callerNode.Out = newOut
	}

	// Remove from callee's In edges
	calleeNode, ok := r.nodes[edge.Callee.Hash]
	if ok {
		newIn := make([]*pb.Edge, 0, len(calleeNode.In))
		for _, e := range calleeNode.In {
			if e != edge {
				newIn = append(newIn, e)
			}
		}
		calleeNode.In = newIn

		if len(calleeNode.In) == 0 {
			r.potentialUnreachable[edge.Callee.Hash] = calleeNode
		}
	}
}

// indexExistingNodes populates r.nodes with existing nodes from the previous call graph.
func (r *IncRTA) indexExistingNodes() {
	if r.result.CallGraph == nil {
		r.result.CallGraph = &pb.CallGraph{}
		return
	}
	for _, node := range r.result.CallGraph.Nodes {
		if node.Function == nil {
			panic("Found node with nil Function in existing CallGraph")
		}
		r.nodes[node.Function.Hash] = node
	}
}

func (r *IncRTA) visitFunc(f *ssa.Function) {
	var space [32]*ssa.Value // preallocate space for common case

	for _, b := range f.Blocks {
		for _, instr := range b.Instrs {
			rands := instr.Operands(space[:0])

			switch instr := instr.(type) {
			case ssa.CallInstruction:
				call := instr.Common()
				if call.IsInvoke() {
					r.visitInvoke(instr)
				} else if g := call.StaticCallee(); g != nil {
					r.addEdge(f, instr, g, false)
				} else if _, ok := call.Value.(*ssa.Builtin); !ok {
					r.visitDynCall(instr)
				}

				// Ignore the call-position operand when
				// looking for address-taken Functions.
				// Hack: assume this is rands[0].
				rands = rands[1:]

			case *ssa.MakeInterface:
				// Converting a value of type T to an
				// interface materializes its runtime
				// type, allowing any of its exported
				// methods to be called though reflection.
				r.summaryAddRuntimeType(f, instr.X.Type())
				r.addRuntimeType(instr.X.Type(), false)
			}

			// Process all address-taken functions.
			for _, op := range rands {
				if g, ok := (*op).(*ssa.Function); ok {
					r.summaryAddFunctionCreated(f, g)
					r.summaryAddProvenance(g, f)
					r.visitAddrTakenFunc(g)
				}
			}
		}
	}
}

func (r *IncRTA) getNode(f *ssa.Function) *pb.Node {
	hash := serializer.HashFunction(f)
	if node, ok := r.nodes[hash]; ok {
		return node
	}

	// Create new node
	pbFn := r.serializer.SerializeFunction(f)
	node := &pb.Node{
		Function: pbFn,
		In:       []*pb.Edge{},
		Out:      []*pb.Edge{},
	}
	r.nodes[hash] = node

	// Since it's new, add to worklist
	r.worklist = append(r.worklist, f)

	// Add to graph nodes list
	r.result.CallGraph.Nodes = append(r.result.CallGraph.Nodes, node)

	return node
}

func (r *IncRTA) addEdge(caller *ssa.Function, site ssa.CallInstruction, callee *ssa.Function, addrTaken bool) {
	callerNode := r.getNode(caller)
	calleeNode := r.getNode(callee)

	// Check if edge exists
	exists := false
	siteHash := serializer.HashCallSite(site)
	for _, e := range callerNode.Out {
		if e.Callee.Hash == calleeNode.Function.Hash && e.Site.Hash == siteHash {
			exists = true
			break
		}
	}

	if !exists {
		edge := &pb.Edge{
			Caller: callerNode.Function,
			Site:   r.serializer.SerializeCallSite(site),
			Callee: calleeNode.Function,
		}
		callerNode.Out = append(callerNode.Out, edge)
		calleeNode.In = append(calleeNode.In, edge)
	}
}

func (r *IncRTA) addEdgeProto(callerNode *pb.Node, site ssa.CallInstruction, calleePbFn *pb.Function) {
	// Find callee node
	var calleeNode *pb.Node
	if node, ok := r.nodes[calleePbFn.Hash]; ok {
		calleeNode = node
	} else {
		// Callee is in RTAState but not in CallGraph?
		calleeNode = &pb.Node{
			Function: calleePbFn,
		}
		r.nodes[calleePbFn.Hash] = calleeNode
		r.result.CallGraph.Nodes = append(r.result.CallGraph.Nodes, calleeNode)
	}

	// Add edge
	exists := false
	siteHash := serializer.HashCallSite(site)
	for _, e := range callerNode.Out {
		if e.Callee.Hash == calleeNode.Function.Hash && e.Site.Hash == siteHash {
			exists = true
			break
		}
	}
	if !exists {
		edge := &pb.Edge{
			Caller: callerNode.Function,
			Site:   r.serializer.SerializeCallSite(site),
			Callee: calleeNode.Function,
		}
		callerNode.Out = append(callerNode.Out, edge)
		calleeNode.In = append(calleeNode.In, edge)
	}
}

func (r *IncRTA) visitDynCall(instr ssa.CallInstruction) {
	sig := instr.Common().Signature().String()

	if funcs, ok := r.result.RTAState.AddrTakenFuncsBySig[sig]; ok {
		for _, pbFn := range funcs.Functions {
			r.addEdgeProto(r.getNode(instr.Parent()), instr, pbFn)
		}
	}

	if r.result.RTAState.DynCallSites == nil {
		r.result.RTAState.DynCallSites = make(map[string]*pb.ListOfCallSites)
	}
	list := r.result.RTAState.DynCallSites[sig]
	if list == nil {
		list = &pb.ListOfCallSites{}
		r.result.RTAState.DynCallSites[sig] = list
	}

	// Check for duplicates
	siteHash := serializer.HashCallSite(instr)
	found := false
	for _, s := range list.CallSites {
		if s.Hash == siteHash {
			found = true
			break
		}
	}
	if !found {
		list.CallSites = append(list.CallSites, r.serializer.SerializeCallSite(instr))
	}
}

func (r *IncRTA) visitAddrTakenFunc(g *ssa.Function) {
	sig := g.Signature.String()
	if r.result.RTAState.AddrTakenFuncsBySig == nil {
		r.result.RTAState.AddrTakenFuncsBySig = make(map[string]*pb.ListOfFunctions)
	}
	list := r.result.RTAState.AddrTakenFuncsBySig[sig]
	if list == nil {
		list = &pb.ListOfFunctions{}
		r.result.RTAState.AddrTakenFuncsBySig[sig] = list
	}

	hash := serializer.HashFunction(g)
	found := false
	for _, f := range list.Functions {
		if f.Hash == hash {
			found = true
			break
		}
	}
	if !found {
		list.Functions = append(list.Functions, r.serializer.SerializeFunction(g))

		// Update existing dynamic calls
		if sites, ok := r.result.RTAState.DynCallSites[sig]; ok {
			for _, site := range sites.CallSites {
				callerHash := site.ParentFunction.Hash
				if callerNode, ok := r.nodes[callerHash]; ok {
					exists := false
					for _, e := range callerNode.Out {
						if e.Callee.Hash == hash && e.Site.Hash == site.Hash {
							exists = true
							break
						}
					}
					if !exists {
						calleeNode := r.getNode(g)
						edge := &pb.Edge{
							Caller: callerNode.Function,
							Site:   site,
							Callee: calleeNode.Function,
						}
						callerNode.Out = append(callerNode.Out, edge)
						calleeNode.In = append(calleeNode.In, edge)
					}
				}
			}
		}
	}
}

func (r *IncRTA) visitInvoke(instr ssa.CallInstruction) {
	// Record the invoke site.
	sig := instr.Common().Value.Type().Underlying().(*types.Interface)
	sigStr := sig.String()

	if r.result.RTAState.InvokeSites == nil {
		r.result.RTAState.InvokeSites = make(map[string]*pb.ListOfCallSites)
	}
	list := r.result.RTAState.InvokeSites[sigStr]
	if list == nil {
		list = &pb.ListOfCallSites{}
		r.result.RTAState.InvokeSites[sigStr] = list
	}

	// Check for duplicates
	siteHash := serializer.HashCallSite(instr)
	found := false
	for _, s := range list.CallSites {
		if s.Hash == siteHash {
			found = true
			break
		}
	}
	if !found {
		list.CallSites = append(list.CallSites, r.serializer.SerializeCallSite(instr))
	}

	// Add callgraph edge for each existing address-taken concrete type implementing I.
	// We iterate over all known concrete types in RTAState.
	for _, ctypeStr := range r.result.RTAState.ConcreteTypes {
		ctype := r.deserializer.GetType(ctypeStr)
		if ctype != nil && types.Implements(ctype, sig) {
			// Ascertain the concrete method of C to be called.
			imethod := instr.Common().Method
			cmethod := r.deserializer.Prog.LookupMethod(ctype, imethod.Pkg(), imethod.Name())
			if cmethod != nil {
				r.addEdge(instr.Parent(), instr, cmethod, true)
			}
		}
	}
}

func (r *IncRTA) addRuntimeType(t types.Type, skip bool) {
	t = types.Unalias(t)
	typeStr := t.String()

	isNew := false
	if prevSkip, ok := r.visitedTypes[typeStr]; ok {
		if !skip && prevSkip {
			// Was skipped, now added. Update status and process as runtime type.
			r.visitedTypes[typeStr] = false
			// Proceed to process as runtime type, but DO NOT recurse (per rta.go logic)
		} else {
			return
		}
	} else {
		isNew = true
		r.visitedTypes[typeStr] = skip
	}

	if !skip {
		// Add to ConcreteTypes if not present
		found := false
		for _, ct := range r.result.RTAState.ConcreteTypes {
			if ct == typeStr {
				found = true
				break
			}
		}
		if !found {
			r.result.RTAState.ConcreteTypes = append(r.result.RTAState.ConcreteTypes, typeStr)
		}

		// Ensure type is in deserializer map
		if r.deserializer.TypesMap == nil {
			r.deserializer.TypesMap = make(map[string]types.Type)
		}
		r.deserializer.TypesMap[typeStr] = t

		// If t is an interface, we don't add edges (it's not a concrete type)
		if _, ok := t.Underlying().(*types.Interface); !ok {
			// Iterate over all known invoke sites and add edges if compatible
			for ifaceStr, sites := range r.result.RTAState.InvokeSites {
				ifaceType := r.deserializer.GetType(ifaceStr)
				if ifaceType == nil {
					continue
				}
				if iface, ok := ifaceType.Underlying().(*types.Interface); ok {
					if types.Implements(t, iface) {
						for _, sitePB := range sites.CallSites {
							site := r.deserializer.DeserializeCallSite(sitePB)
							if site != nil {
								imethod := site.Common().Method
								cmethod := r.deserializer.Prog.LookupMethod(t, imethod.Pkg(), imethod.Name())
								if cmethod != nil {
									r.addEdge(site.Parent(), site, cmethod, true)
								}
							}
						}
					}
				}
			}
		}
	}

	if !isNew {
		return
	}

	// Recursively add types (simplified version of rta.go logic)
	var n *types.Named
	switch T := types.Unalias(t).(type) {
	case *types.Named:
		n = T
	case *types.Pointer:
		n, _ = types.Unalias(T.Elem()).(*types.Named)
	}
	if n != nil {
		owner := n.Obj().Pkg()
		if owner == nil {
			return // built-in error type
		}
	}

	mset := r.deserializer.Prog.MethodSets.MethodSet(t)
	// Recursion over signatures of each exported method.
	for i := 0; i < mset.Len(); i++ {
		if mset.At(i).Obj().Exported() {
			sig := mset.At(i).Type().(*types.Signature)
			r.addRuntimeType(sig.Params(), true)  // skip the Tuple itself
			r.addRuntimeType(sig.Results(), true) // skip the Tuple itself
		}
	}

	switch t := t.(type) {
	case *types.Alias:
		panic("unreachable")

	case *types.Basic:
		// nop

	case *types.Interface:
		// nop---handled by recursion over method set.

	case *types.Pointer:
		r.addRuntimeType(t.Elem(), false)

	case *types.Slice:
		r.addRuntimeType(t.Elem(), false)

	case *types.Chan:
		r.addRuntimeType(t.Elem(), false)

	case *types.Map:
		r.addRuntimeType(t.Key(), false)
		r.addRuntimeType(t.Elem(), false)

	case *types.Signature:
		if t.Recv() != nil {
			// panic(fmt.Sprintf("Signature %s has Recv %s", t, t.Recv()))
		}
		r.addRuntimeType(t.Params(), true)  // skip the Tuple itself
		r.addRuntimeType(t.Results(), true) // skip the Tuple itself

	case *types.Named:
		// A pointer-to-named type can be derived from a named
		// type via reflection.  It may have methods too.
		r.addRuntimeType(types.NewPointer(t), false)

		// Consider 'type T struct{S}' where S has methods.
		// Reflection provides no way to get from T to struct{S},
		// only to S, so the method set of struct{S} is unwanted,
		// so set 'skip' flag during recursion.
		r.addRuntimeType(t.Underlying(), true)

	case *types.Array:
		r.addRuntimeType(t.Elem(), false)

	case *types.Struct:
		for i, n := 0, t.NumFields(); i < n; i++ {
			r.addRuntimeType(t.Field(i).Type(), false)
		}

	case *types.Tuple:
		for i, n := 0, t.Len(); i < n; i++ {
			r.addRuntimeType(t.At(i).Type(), false)
		}
	}
}

func (r *IncRTA) summaryAddRuntimeType(f *ssa.Function, t types.Type) {
	// Update summary
	hash := serializer.HashFunction(f)
	if r.result.RTAState.Summary == nil {
		r.result.RTAState.Summary = make(map[string]*pb.MethodSummary)
	}

	summary := r.result.RTAState.Summary[hash]
	if summary == nil {
		summary = &pb.MethodSummary{}
		r.result.RTAState.Summary[hash] = summary
	}

	// Add a provenance for every function in T's method set.
	mset := r.deserializer.Prog.MethodSets.MethodSet(t)
	for i := 0; i < mset.Len(); i++ {
		sel := mset.At(i)
		m := r.deserializer.Prog.MethodValue(sel)
		if m == nil {
			continue
		}

		mHash := serializer.HashFunction(m)
		mSummary := r.result.RTAState.Summary[mHash]
		if mSummary == nil {
			mSummary = &pb.MethodSummary{}
			r.result.RTAState.Summary[mHash] = mSummary
		}

		// creator created m, so add m to creator's FunctionsCreated
		// Check for duplicates
		found := false
		for _, fc := range summary.FunctionsCreated {
			if fc.Hash == mHash {
				found = true
				break
			}
		}
		if !found {
			summary.FunctionsCreated = append(summary.FunctionsCreated, r.serializer.SerializeFunction(m))
		}

		// m was created by creator, so add creator to m's Provenance
		found = false
		for _, p := range mSummary.Provenance {
			if p.Hash == hash {
				found = true
				break
			}
		}
		if !found {
			mSummary.Provenance = append(mSummary.Provenance, r.serializer.SerializeFunction(f))
		}
	}
}

func (r *IncRTA) summaryAddFunctionCreated(f *ssa.Function, g *ssa.Function) {
	hash := serializer.HashFunction(f)
	if r.result.RTAState.Summary == nil {
		r.result.RTAState.Summary = make(map[string]*pb.MethodSummary)
	}
	summary := r.result.RTAState.Summary[hash]
	if summary == nil {
		summary = &pb.MethodSummary{}
		r.result.RTAState.Summary[hash] = summary
	}

	gHash := serializer.HashFunction(g)
	found := false
	for _, created := range summary.FunctionsCreated {
		if created.Hash == gHash {
			found = true
			break
		}
	}
	if !found {
		summary.FunctionsCreated = append(summary.FunctionsCreated, r.serializer.SerializeFunction(g))
	}
}

func (r *IncRTA) summaryAddProvenance(g *ssa.Function, f *ssa.Function) {
	// Similar to summaryAddFunctionCreated but for Provenance of g
	hash := serializer.HashFunction(g)
	if r.result.RTAState.Summary == nil {
		r.result.RTAState.Summary = make(map[string]*pb.MethodSummary)
	}
	summary := r.result.RTAState.Summary[hash]
	if summary == nil {
		summary = &pb.MethodSummary{}
		r.result.RTAState.Summary[hash] = summary
	}

	fHash := serializer.HashFunction(f)
	found := false
	for _, prov := range summary.Provenance {
		if prov.Hash == fHash {
			found = true
			break
		}
	}
	if !found {
		summary.Provenance = append(summary.Provenance, r.serializer.SerializeFunction(f))
	}
}
