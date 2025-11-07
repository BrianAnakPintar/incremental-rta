package rta

import "golang.org/x/tools/go/callgraph"

/*
	This file contains functions which are meant to help with incremental RTA,
	in particular, this contains functions which are meant to be placed in callgraph.go
	but are placed here to make things easier for now.
*/

// removeOutEdge removes edge.Caller's outgoing edge 'edge'.
func removeOutEdge(edge *callgraph.Edge) {
	caller := edge.Caller
	n := len(caller.Out)
	for i, e := range caller.Out {
		if e == edge {
			// Replace it with the final element and shrink the slice.
			caller.Out[i] = caller.Out[n-1]
			caller.Out[n-1] = nil // aid GC
			caller.Out = caller.Out[:n-1]
			return
		}
	}
	panic("edge not found: " + edge.String())
}

// removeInEdge removes edge.Callee's incoming edge 'edge'.
func removeInEdge(edge *callgraph.Edge) {
	callee := edge.Callee
	n := len(callee.In)
	for i, e := range callee.In {
		if e == edge {
			// Replace it with the final element and shrink the slice.
			callee.In[i] = callee.In[n-1]
			callee.In[n-1] = nil // aid GC
			callee.In = callee.In[:n-1]
			return
		}
	}
	panic("edge not found: " + edge.String())
}

func removeEdge(edge *callgraph.Edge) {
	removeOutEdge(edge)
	removeInEdge(edge)
}
