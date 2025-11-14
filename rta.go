// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This package provides Rapid Type Analysis (RTA) for Go, a fast
// algorithm for call graph construction and discovery of reachable code
// (and hence dead code) and runtime types.  The algorithm was first
// described in:
//
// David F. Bacon and Peter F. Sweeney. 1996.
// Fast static analysis of C++ virtual function calls. (OOPSLA '96)
// http://doi.acm.org/10.1145/236337.236371
//
// The algorithm uses dynamic programming to tabulate the cross-product
// of the set of known "address-taken" functions with the set of known
// dynamic calls of the same type.  As each new address-taken function
// is discovered, call graph edges are added from each known callsite,
// and as each new call site is discovered, call graph edges are added
// from it to each known address-taken function.
//
// A similar approach is used for dynamic calls via interfaces: it
// tabulates the cross-product of the set of known "runtime types",
// i.e. types that may appear in an interface value, or may be derived from
// one via reflection, with the set of known "invoke"-mode dynamic
// calls.  As each new runtime type is discovered, call edges are
// added from the known call sites, and as each new call site is
// discovered, call graph edges are added to each compatible
// method.
//
// In addition, we must consider as reachable all address-taken
// functions and all exported methods of any runtime type, since they
// may be called via reflection.
//
// Each time a newly added call edge causes a new function to become
// reachable, the code of that function is analyzed for more call sites,
// address-taken functions, and runtime types.  The process continues
// until a fixed point is reached.
package rta // import "golang.org/x/tools/go/callgraph/rta"

import (
	"fmt"
	"go/types"
	"hash/crc32"
	"strings"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/types/typeutil"
)

type MethodSummary struct {
	// Functions that contributed to the creation of this method
	Provenance []*ssa.Function

	// Functions created as a result of this method
	FunctionsCreated []*ssa.Function
}

// A Result holds the results of Rapid Type Analysis, which includes the
// set of reachable functions/methods, runtime types, and the call graph.
type Result struct {
	// CallGraph is the discovered callgraph.
	// It does not include edges for calls made via reflection.
	CallGraph *callgraph.Graph

	// Reachable contains the set of reachable functions and methods.
	// This includes exported methods of runtime types, since
	// they may be accessed via reflection.
	// The value indicates whether the function is address-taken.
	//
	// (We wrap the bool in a struct to avoid inadvertent use of
	// "if Reachable[f] {" to test for set membership.)
	Reachable map[*ssa.Function]struct{ AddrTaken bool }

	// RuntimeTypes contains the set of types that are needed at
	// runtime, for interfaces or reflection.
	//
	// The value indicates whether the type is inaccessible to reflection.
	// Consider:
	// 	type A struct{B}
	// 	fmt.Println(new(A))
	// Types *A, A and B are accessible to reflection, but the unnamed
	// type struct{B} is not.
	RuntimeTypes typeutil.Map
}

// Working state of the RTA algorithm.
type rta struct {
	result *Result

	prog *ssa.Program

	reflectValueCall *ssa.Function // (*reflect.Value).Call, iff part of prog

	worklist []*ssa.Function // list of functions to visit

	// addrTakenFuncsBySig contains all address-taken *Functions, grouped by signature.
	// Keys are *types.Signature, values are map[*ssa.Function]bool sets.
	addrTakenFuncsBySig typeutil.Map

	// dynCallSites contains all dynamic "call"-mode call sites, grouped by signature.
	// Keys are *types.Signature, values are unordered []ssa.CallInstruction.
	dynCallSites typeutil.Map

	// invokeSites contains all "invoke"-mode call sites, grouped by interface.
	// Keys are *types.Interface (never *types.Named),
	// Values are unordered []ssa.CallInstruction sets.
	invokeSites typeutil.Map

	// The following two maps together define the subset of the
	// m:n "implements" relation needed by the algorithm.

	// concreteTypes maps each concrete type to information about it.
	// Keys are types.Type, values are *concreteTypeInfo.
	// Only concrete types used as MakeInterface operands are included.
	concreteTypes typeutil.Map

	// interfaceTypes maps each interface type to information about it.
	// Keys are *types.Interface, values are *interfaceTypeInfo.
	// Only interfaces used in "invoke"-mode CallInstructions are included.
	interfaceTypes typeutil.Map

	// Methods maps each method to its summary information.
	summary map[*ssa.Function]*MethodSummary

	// Roots of the call graph.
	roots []*ssa.Function

	// True if the call graph has been modified since last traversal.
	dirtyCG bool

	traversable map[*callgraph.Node]bool
}

type concreteTypeInfo struct {
	C          types.Type
	mset       *types.MethodSet
	fprint     uint64             // fingerprint of method set
	implements []*types.Interface // unordered set of implemented interfaces
}

type interfaceTypeInfo struct {
	I               *types.Interface
	mset            *types.MethodSet
	fprint          uint64
	implementations []types.Type // unordered set of concrete implementations
}

// addReachable marks a function as potentially callable at run-time,
// and ensures that it gets processed.
func (r *rta) addReachable(f *ssa.Function, addrTaken bool) {
	reachable := r.result.Reachable
	n := len(reachable)
	v := reachable[f]
	if addrTaken {
		v.AddrTaken = true
	}
	reachable[f] = v
	if len(reachable) > n {
		// First time seeing f.  Add it to the worklist.
		r.worklist = append(r.worklist, f)
	}
}

// addEdge adds the specified call graph edge, and marks it reachable.
// addrTaken indicates whether to mark the callee as "address-taken".
// site is nil for calls made via reflection.
func (r *rta) addEdge(caller *ssa.Function, site ssa.CallInstruction, callee *ssa.Function, addrTaken bool) {
	r.addReachable(callee, addrTaken)

	if g := r.result.CallGraph; g != nil {
		if caller == nil {
			panic(site)
		}
		from := g.CreateNode(caller)
		to := g.CreateNode(callee)
		callgraph.AddEdge(from, site, to)
	}
}

// ---------- addrTakenFuncs × dynCallSites ----------

// visitAddrTakenFunc is called each time we encounter an address-taken function f.
func (r *rta) visitAddrTakenFunc(f *ssa.Function) {
	// Create two-level map (Signature -> Function -> bool).
	S := f.Signature
	funcs, _ := r.addrTakenFuncsBySig.At(S).(map[*ssa.Function]bool)
	if funcs == nil {
		funcs = make(map[*ssa.Function]bool)
		r.addrTakenFuncsBySig.Set(S, funcs)
	}
	if !funcs[f] {
		// First time seeing f.
		funcs[f] = true

		// If we've seen any dyncalls of this type, mark it reachable,
		// and add call graph edges.
		sites, _ := r.dynCallSites.At(S).([]ssa.CallInstruction)
		for _, site := range sites {
			r.addEdge(site.Parent(), site, f, true)
		}

		// If the program includes (*reflect.Value).Call,
		// add a dynamic call edge from it to any address-taken
		// function, regardless of signature.
		//
		// This isn't perfect.
		// - The actual call comes from an internal function
		//   called reflect.call, but we can't rely on that here.
		// - reflect.Value.CallSlice behaves similarly,
		//   but we don't bother to create callgraph edges from
		//   it as well as it wouldn't fundamentally change the
		//   reachability but it would add a bunch more edges.
		// - We assume that if reflect.Value.Call is among
		//   the dependencies of the application, it is itself
		//   reachable. (It would be more accurate to defer
		//   all the addEdges below until r.V.Call itself
		//   becomes reachable.)
		// - Fake call graph edges are added from r.V.Call to
		//   each address-taken function, but not to every
		//   method reachable through a materialized rtype,
		//   which is a little inconsistent. Still, the
		//   reachable set includes both kinds, which is what
		//   matters for e.g. deadcode detection.)
		if r.reflectValueCall != nil {
			var site ssa.CallInstruction = nil // can't find actual call site
			r.addEdge(r.reflectValueCall, site, f, true)
		}
	}
}

// visitDynCall is called each time we encounter a dynamic "call"-mode call.
func (r *rta) visitDynCall(site ssa.CallInstruction) {
	S := site.Common().Signature()

	// Record the call site.
	sites, _ := r.dynCallSites.At(S).([]ssa.CallInstruction)
	r.dynCallSites.Set(S, append(sites, site))

	// For each function of signature S that we know is address-taken,
	// add an edge and mark it reachable.
	funcs, _ := r.addrTakenFuncsBySig.At(S).(map[*ssa.Function]bool)
	for g := range funcs {
		r.addEdge(site.Parent(), site, g, true)
	}
}

// ---------- concrete types × invoke sites ----------

// addInvokeEdge is called for each new pair (site, C) in the matrix.
func (r *rta) addInvokeEdge(site ssa.CallInstruction, C types.Type) {
	// Ascertain the concrete method of C to be called.
	imethod := site.Common().Method
	cmethod := r.prog.LookupMethod(C, imethod.Pkg(), imethod.Name())
	r.addEdge(site.Parent(), site, cmethod, true)
}

// visitInvoke is called each time the algorithm encounters an "invoke"-mode call.
func (r *rta) visitInvoke(site ssa.CallInstruction) {
	I := site.Common().Value.Type().Underlying().(*types.Interface)

	// Record the invoke site.
	sites, _ := r.invokeSites.At(I).([]ssa.CallInstruction)
	r.invokeSites.Set(I, append(sites, site))

	// Add callgraph edge for each existing
	// address-taken concrete type implementing I.
	for _, C := range r.implementations(I) {
		r.addInvokeEdge(site, C)
	}
}

// ---------- main algorithm ----------

// visitFunc processes function f.
func (r *rta) visitFunc(f *ssa.Function) {
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

// Analyze performs Rapid Type Analysis, starting at the specified root
// functions.  It returns nil if no roots were specified.
//
// The root functions must be one or more entrypoints (main and init
// functions) of a complete SSA program, with function bodies for all
// dependencies, constructed with the [ssa.InstantiateGenerics] mode
// flag.
//
// If buildCallGraph is true, Result.CallGraph will contain a call
// graph; otherwise, only the other fields (reachable functions) are
// populated.
func Analyze(roots []*ssa.Function, buildCallGraph bool) *Result {
	if len(roots) == 0 {
		return nil
	}

	r := &rta{
		result:      &Result{Reachable: make(map[*ssa.Function]struct{ AddrTaken bool })},
		prog:        roots[0].Prog,
		summary:     make(map[*ssa.Function]*MethodSummary),
		traversable: make(map[*callgraph.Node]bool),
		dirtyCG:     true,
	}

	if buildCallGraph {
		// TODO(adonovan): change callgraph API to eliminate the
		// notion of a distinguished root node.  Some callgraphs
		// have many roots, or none.
		r.result.CallGraph = callgraph.New(roots[0])
	}

	// Grab ssa.Function for (*reflect.Value).Call,
	// if "reflect" is among the dependencies.
	if reflectPkg := r.prog.ImportedPackage("reflect"); reflectPkg != nil {
		reflectValue := reflectPkg.Members["Value"].(*ssa.Type)
		r.reflectValueCall = r.prog.LookupMethod(reflectValue.Object().Type(), reflectPkg.Pkg, "Call")
	}

	hasher := typeutil.MakeHasher()
	r.result.RuntimeTypes.SetHasher(hasher)
	r.addrTakenFuncsBySig.SetHasher(hasher)
	r.dynCallSites.SetHasher(hasher)
	r.invokeSites.SetHasher(hasher)
	r.concreteTypes.SetHasher(hasher)
	r.interfaceTypes.SetHasher(hasher)

	for _, root := range roots {
		r.addReachable(root, false)
	}

	// Visit functions, processing their instructions, and adding
	// new functions to the worklist, until a fixed point is
	// reached.
	var shadow []*ssa.Function // for efficiency, we double-buffer the worklist
	for len(r.worklist) > 0 {
		shadow, r.worklist = r.worklist, shadow[:0]
		for _, f := range shadow {
			r.visitFunc(f)
		}
	}
	return r.result
}

// AnalyzeAndSaveState performs Rapid Type Analysis and returns both the result
// and the internal state needed for incremental analysis.
// This is a convenience wrapper around Analyze that prepares state for IncrementalAnalyze.
func AnalyzeAndSaveState(roots []*ssa.Function, buildCallGraph bool) *ResultWithState {
	if len(roots) == 0 {
		return nil
	}

	r := &rta{
		result:      &Result{Reachable: make(map[*ssa.Function]struct{ AddrTaken bool })},
		prog:        roots[0].Prog,
		summary:     make(map[*ssa.Function]*MethodSummary),
		roots:       roots,
		traversable: make(map[*callgraph.Node]bool),
		dirtyCG:     true,
	}

	if buildCallGraph {
		r.result.CallGraph = callgraph.New(roots[0])
	}

	// Grab ssa.Function for (*reflect.Value).Call,
	// if "reflect" is among the dependencies.
	if reflectPkg := r.prog.ImportedPackage("reflect"); reflectPkg != nil {
		reflectValue := reflectPkg.Members["Value"].(*ssa.Type)
		r.reflectValueCall = r.prog.LookupMethod(reflectValue.Object().Type(), reflectPkg.Pkg, "Call")
	}

	hasher := typeutil.MakeHasher()
	r.result.RuntimeTypes.SetHasher(hasher)
	r.addrTakenFuncsBySig.SetHasher(hasher)
	r.dynCallSites.SetHasher(hasher)
	r.invokeSites.SetHasher(hasher)
	r.concreteTypes.SetHasher(hasher)
	r.interfaceTypes.SetHasher(hasher)

	for _, root := range roots {
		r.addReachable(root, false)
	}

	// Visit functions, processing their instructions, and adding
	// new functions to the worklist, until a fixed point is
	// reached.
	var shadow []*ssa.Function // for efficiency, we double-buffer the worklist
	for len(r.worklist) > 0 {
		shadow, r.worklist = r.worklist, shadow[:0]
		for _, f := range shadow {
			r.visitFunc(f)
		}
	}

	return &ResultWithState{
		Result: r.result,
		State:  saveRTAState(r),
	}
}

// interfaces(C) returns all currently known interfaces implemented by C.
func (r *rta) interfaces(C types.Type) []*types.Interface {
	// Create an info for C the first time we see it.
	var cinfo *concreteTypeInfo
	if v := r.concreteTypes.At(C); v != nil {
		cinfo = v.(*concreteTypeInfo)
	} else {
		mset := r.prog.MethodSets.MethodSet(C)
		cinfo = &concreteTypeInfo{
			C:      C,
			mset:   mset,
			fprint: fingerprint(mset),
		}
		r.concreteTypes.Set(C, cinfo)

		// Ascertain set of interfaces C implements
		// and update the 'implements' relation.
		r.interfaceTypes.Iterate(func(I types.Type, v any) {
			iinfo := v.(*interfaceTypeInfo)
			if I := types.Unalias(I).(*types.Interface); implements(cinfo, iinfo) {
				iinfo.implementations = append(iinfo.implementations, C)
				cinfo.implements = append(cinfo.implements, I)
			}
		})
	}

	return cinfo.implements
}

// implementations(I) returns all currently known concrete types that implement I.
func (r *rta) implementations(I *types.Interface) []types.Type {
	// Create an info for I the first time we see it.
	var iinfo *interfaceTypeInfo
	if v := r.interfaceTypes.At(I); v != nil {
		iinfo = v.(*interfaceTypeInfo)
	} else {
		mset := r.prog.MethodSets.MethodSet(I)
		iinfo = &interfaceTypeInfo{
			I:      I,
			mset:   mset,
			fprint: fingerprint(mset),
		}
		r.interfaceTypes.Set(I, iinfo)

		// Ascertain set of concrete types that implement I
		// and update the 'implements' relation.
		r.concreteTypes.Iterate(func(C types.Type, v any) {
			cinfo := v.(*concreteTypeInfo)
			if implements(cinfo, iinfo) {
				cinfo.implements = append(cinfo.implements, I)
				iinfo.implementations = append(iinfo.implementations, C)
			}
		})
	}
	return iinfo.implementations
}

// addRuntimeType is called for each concrete type that can be the
// dynamic type of some interface or reflect.Value.
// Adapted from needMethods in go/ssa/builder.go
func (r *rta) addRuntimeType(T types.Type, skip bool) {
	// Never record aliases.
	T = types.Unalias(T)

	if prev, ok := r.result.RuntimeTypes.At(T).(bool); ok {
		if skip && !prev {
			r.result.RuntimeTypes.Set(T, skip)
		}
		return
	}
	r.result.RuntimeTypes.Set(T, skip)

	mset := r.prog.MethodSets.MethodSet(T)

	if _, ok := T.Underlying().(*types.Interface); !ok {
		// T is a new concrete type.
		for i, n := 0, mset.Len(); i < n; i++ {
			sel := mset.At(i)
			m := sel.Obj()

			if m.Exported() {
				// Exported methods are always potentially callable via reflection.
				r.addReachable(r.prog.MethodValue(sel), true)
			}
		}

		// Add callgraph edge for each existing dynamic
		// "invoke"-mode call via that interface.
		for _, I := range r.interfaces(T) {
			sites, _ := r.invokeSites.At(I).([]ssa.CallInstruction)
			for _, site := range sites {
				r.addInvokeEdge(site, T)
			}
		}
	}

	// Precondition: T is not a method signature (*Signature with Recv()!=nil).
	// Recursive case: skip => don't call makeMethods(T).
	// Each package maintains its own set of types it has visited.

	var n *types.Named
	switch T := types.Unalias(T).(type) {
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

	// Recursion over signatures of each exported method.
	for i := 0; i < mset.Len(); i++ {
		if mset.At(i).Obj().Exported() {
			sig := mset.At(i).Type().(*types.Signature)
			r.addRuntimeType(sig.Params(), true)  // skip the Tuple itself
			r.addRuntimeType(sig.Results(), true) // skip the Tuple itself
		}
	}

	switch t := T.(type) {
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
			panic(fmt.Sprintf("Signature %s has Recv %s", t, t.Recv()))
		}
		r.addRuntimeType(t.Params(), true)  // skip the Tuple itself
		r.addRuntimeType(t.Results(), true) // skip the Tuple itself

	case *types.Named:
		// A pointer-to-named type can be derived from a named
		// type via reflection.  It may have methods too.
		r.addRuntimeType(types.NewPointer(T), false)

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

	default:
		panic(T)
	}
}

// fingerprint returns a bitmask with one bit set per method id,
// enabling 'implements' to quickly reject most candidates.
func fingerprint(mset *types.MethodSet) uint64 {
	var space [64]byte
	var mask uint64
	for i := 0; i < mset.Len(); i++ {
		method := mset.At(i).Obj()
		sig := method.Type().(*types.Signature)
		sum := crc32.ChecksumIEEE(fmt.Appendf(space[:], "%s/%d/%d",
			method.Id(),
			sig.Params().Len(),
			sig.Results().Len()))
		mask |= 1 << (sum % 64)
	}
	return mask
}

// implements reports whether types.Implements(cinfo.C, iinfo.I),
// but more efficiently.
func implements(cinfo *concreteTypeInfo, iinfo *interfaceTypeInfo) (got bool) {
	// The concrete type must have at least the methods
	// (bits) of the interface type. Use a bitwise subset
	// test to reject most candidates quickly.
	return iinfo.fprint & ^cinfo.fprint == 0 && types.Implements(cinfo.C, iinfo.I)
}

// Contains the state needed to perform incremental RTA.
type RTAState struct {
	Roots            []*ssa.Function
	ReflectValueCall *ssa.Function

	AddrTakenFuncsBySig typeutil.Map
	DynCallSites        typeutil.Map
	InvokeSites         typeutil.Map
	ConcreteTypes       typeutil.Map
	InterfaceTypes      typeutil.Map

	Summary map[*ssa.Function]*MethodSummary
}

type ResultWithState struct {
	Result *Result
	State  *RTAState
}

func (r *rta) summaryAddRuntimeType(creator *ssa.Function, T types.Type) {
	if _, ok := r.summary[creator]; !ok {
		r.summary[creator] = &MethodSummary{
			Provenance:       make([]*ssa.Function, 0),
			FunctionsCreated: make([]*ssa.Function, 0),
		}
	}

	// Add a provenance for every function in T's method set.
	mset := r.prog.MethodSets.MethodSet(T)
	for i := 0; i < mset.Len(); i++ {
		sel := mset.At(i)
		m := r.prog.MethodValue(sel)

		if _, ok := r.summary[m]; !ok {
			r.summary[m] = &MethodSummary{
				Provenance:       make([]*ssa.Function, 0),
				FunctionsCreated: make([]*ssa.Function, 0),
			}
		}

		// creator created m, so add m to creator's FunctionsCreated
		r.summary[creator].FunctionsCreated = append(r.summary[creator].FunctionsCreated, m)
		// m was created by creator, so add creator to m's Provenance
		r.summary[m].Provenance = append(r.summary[m].Provenance, creator)
	}
}

func (r *rta) summaryAddFunctionCreated(owner *ssa.Function, created *ssa.Function) {
	if _, ok := r.summary[owner]; !ok {
		r.summary[owner] = &MethodSummary{
			Provenance:       make([]*ssa.Function, 0),
			FunctionsCreated: make([]*ssa.Function, 0),
		}
	}
	r.summary[owner].FunctionsCreated = append(r.summary[owner].FunctionsCreated, created)
}

func (r *rta) summaryAddProvenance(owner *ssa.Function, prov *ssa.Function) {
	if _, ok := r.summary[owner]; !ok {
		r.summary[owner] = &MethodSummary{
			Provenance:       make([]*ssa.Function, 0),
			FunctionsCreated: make([]*ssa.Function, 0),
		}
	}
	r.summary[owner].Provenance = append(r.summary[owner].Provenance, prov)
}

// IncrementalAnalyze performs RTA starting from the given roots.
// If prevRun is nil, it behaves like Analyze but returns the analysis state as well.
// If prevRun is !nil, it reuses the analysis state and roots would be the changed functions.
// roots are functions that are entrypoints or have changed since the last analysis.

// NOTE: For now let's assume that it always builds the call graph.
func IncrementalAnalyze(roots []*ssa.Function, prevRun *ResultWithState) *ResultWithState {
	// TODO(brian): Consider the case of removing a root. This would require us to prune the CG.
	if prevRun == nil {
		panic("Cannot do incremental analysis without prevRun")
	}

	if len(roots) == 0 {
		return prevRun
	}

	r := &rta{
		result:      prevRun.Result,
		prog:        roots[0].Prog,
		summary:     prevRun.State.Summary,
		traversable: make(map[*callgraph.Node]bool),
		dirtyCG:     true,
	}

	if r.result.CallGraph == nil {
		r.result.CallGraph = callgraph.New(roots[0])
	}

	// Refill the RTA state from previous run
	refillRTAState(r, prevRun.State)

	// Ensure concrete/interface maps have hashers (in case prev state was nil
	// or came from an older run). Use the same hasher as the runtime types map
	// so keys (types.Type) are hashed consistently.
	hasher := typeutil.MakeHasher()
	r.result.RuntimeTypes.SetHasher(hasher)
	r.concreteTypes.SetHasher(hasher)
	r.interfaceTypes.SetHasher(hasher)

	// Populate concreteTypes and interfaceTypes from previously discovered
	// runtime types so that implementations/interfaces queries work
	// incrementally. These maps are created lazily in the non-incremental
	// analysis, so we must ensure they exist and are filled for previously
	// observed runtime types.
	r.result.RuntimeTypes.Iterate(func(T types.Type, _ any) {
		if T == nil {
			return
		}
		// If T is an interface type, make sure its interface info exists.
		if _, ok := types.Unalias(T).Underlying().(*types.Interface); ok {
			// implementations will create interfaceTypeInfo and iterate existing
			// concreteTypes to populate implementations.
			r.implementations(types.Unalias(T).Underlying().(*types.Interface))
			return
		}
		// Otherwise T is a concrete type: create its concreteTypeInfo and
		// record which interfaces it implements.
		r.interfaces(T)
	})

	// Collect functions that may become unreachable after removing edges
	potentialFuncs := make([]*ssa.Function, 0)

	// Grab ssa.Function for (*reflect.Value).Call,
	// if "reflect" is among the dependencies.
	if reflectPkg := r.prog.ImportedPackage("reflect"); reflectPkg != nil {
		reflectValue := reflectPkg.Members["Value"].(*ssa.Type)
		r.reflectValueCall = r.prog.LookupMethod(reflectValue.Object().Type(), reflectPkg.Pkg, "Call")
	}

	// For each changed function, remove its outgoing edges and re-analyze
	for _, root := range roots {
		// Collect potential functions before removing edges
		if node := r.result.CallGraph.Nodes[root]; node != nil {
			for _, edge := range node.Out {
				potentialFuncs = append(potentialFuncs, edge.Callee.Func)
			}
		}
		r.removeOutgoingEdges(root)
		summary := r.summary[root]
		if summary == nil {
			delete(r.result.Reachable, root)
			r.addReachable(root, false)
			continue
		}

		funcsCreated := summary.FunctionsCreated
		for _, fn := range funcsCreated {
			r.removeBasedOnProvenance(root, fn)
			potentialFuncs = append(potentialFuncs, fn)
		}

		delete(r.result.Reachable, root)
		r.addReachable(root, false)
	}

	// Process the worklist
	var shadow []*ssa.Function // for efficiency, we double-buffer the worklist
	for len(r.worklist) > 0 {
		shadow, r.worklist = r.worklist, shadow[:0]
		for _, f := range shadow {
			r.visitFunc(f)
		}
	}

	// Prune functions that are no longer reachable
	r.TraversabilityCheck()

	for len(potentialFuncs) > 0 {
		fn := potentialFuncs[len(potentialFuncs)-1]
		potentialFuncs = potentialFuncs[:len(potentialFuncs)-1]

		node := r.result.CallGraph.Nodes[fn]
		if r.traversable[node] {
			continue
		}

		if node != nil {
			for _, edge := range node.Out {
				potentialFuncs = append(potentialFuncs, edge.Callee.Func)
			}
		}
		r.removeOutgoingEdges(fn)

		delete(r.result.Reachable, fn)
		delete(r.result.CallGraph.Nodes, fn)

		summary := r.summary[fn]
		if summary != nil {
			funcsCreated := summary.FunctionsCreated
			for _, fnCreated := range funcsCreated {
				r.removeBasedOnProvenance(fn, fnCreated)
				potentialFuncs = append(potentialFuncs, fnCreated)
			}
		}
	}

	res := &ResultWithState{
		Result: r.result,
		State:  saveRTAState(r),
	}
	return res
}

func saveRTAState(r *rta) *RTAState {
	return &RTAState{
		Roots:               r.roots,
		ReflectValueCall:    r.reflectValueCall,
		AddrTakenFuncsBySig: r.addrTakenFuncsBySig,
		DynCallSites:        r.dynCallSites,
		InvokeSites:         r.invokeSites,
		ConcreteTypes:       r.concreteTypes,
		InterfaceTypes:      r.interfaceTypes,
		Summary:             r.summary,
	}
}

func refillRTAState(r *rta, state *RTAState) {
	r.roots = state.Roots
	r.reflectValueCall = state.ReflectValueCall
	r.addrTakenFuncsBySig = state.AddrTakenFuncsBySig
	r.dynCallSites = state.DynCallSites
	r.invokeSites = state.InvokeSites
	r.concreteTypes = state.ConcreteTypes
	r.interfaceTypes = state.InterfaceTypes
	r.summary = state.Summary
}

func (r *rta) removeOutgoingEdges(f *ssa.Function) {
	cg := r.result.CallGraph
	if cg == nil {
		panic("No graph in rta, we require a graph to be built for now.")
	}

	nd := cg.Nodes[f]
	if nd == nil {
		// No outgoing edges to remove
		return
	}

	// Remove all outgoing edges and update incoming edges of callees
	outEdges := nd.Out
	for _, outEdge := range outEdges {
		outNode := outEdge.Callee
		filterOutNodeFromIncomingEdges(outNode, nd)
	}
	nd.Out = nil

	cg.Nodes[f] = nd
}

// super verbose name? TODO: ask AI to find better name.
func filterOutNodeFromIncomingEdges(outNode *callgraph.Node, ndToRemove *callgraph.Node) {
	// Remove incoming edge from outNode
	newIn := outNode.In[:0]
	for _, inEdge := range outNode.In {
		if inEdge.Caller == ndToRemove {
			continue
		}
		newIn = append(newIn, inEdge)
	}
	outNode.In = newIn
}

// prov is a function that contributed to the creation of fn.
// If all provenance functions of fn are no longer reachable, remove fn as well.
func (r *rta) removeBasedOnProvenance(prov *ssa.Function, fn *ssa.Function) {
	// remove prov from fn's provenance
	summary, ok := r.summary[fn]
	if !ok {
		return
	}

	// Remove prov from provenance
	newProvenance := make([]*ssa.Function, 0)
	for _, p := range summary.Provenance {
		if p != prov {
			newProvenance = append(newProvenance, p)
		}
	}
	summary.Provenance = newProvenance
	r.summary[fn] = summary

	// If provenance is now empty, remove all dynamic in edges to fn
	if len(summary.Provenance) == 0 {
		cg := r.result.CallGraph
		if cg == nil {
			panic("No graph in rta, we require a graph to be built for now.")
		}

		nd := cg.Nodes[fn]
		if nd == nil {
			return
		}

		// Remove all incoming edges and update outgoing edges of callers
		// At some point we may want to distinguish between dynamic method and function calls.
		inEdges := nd.In
		for _, edge := range inEdges {
			if strings.Contains(edge.Description(), "dynamic") {
				removeOutEdge(edge)
				removeInEdge(edge)
			}
		}
		nd.In = nil
		cg.Nodes[fn] = nd

		if len(nd.In) == 0 {
			// No incoming edges, remove from reachable set
			delete(r.result.Reachable, fn)
		}

		// Mark call graph as dirty for traversal check
		r.dirtyCG = true
	}

}

func (r *rta) TraversabilityCheck() {
	for _, root := range r.roots {
		r.MarkTraversable(r.result.CallGraph.Nodes[root])
	}
	r.dirtyCG = false
}

func (r *rta) MarkTraversable(node *callgraph.Node) {
	if r.traversable[node] {
		return
	}
	r.traversable[node] = true

	// Simple DFS
	for _, edge := range node.Out {
		r.MarkTraversable(edge.Callee)
	}
}
