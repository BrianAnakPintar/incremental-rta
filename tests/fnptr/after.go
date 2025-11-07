package main

type FP func()

func main() {
	f := A
	f()
	callFP(C)
}

func callFP(fn FP) { fn() }

func A() {}
func B() {}
func C() {}
