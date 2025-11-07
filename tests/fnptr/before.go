package main

type FP func()

func main() {
	f := A
	f()
	callFP(B)
}

func callFP(fn FP) { fn() }

func A() {}
func B() {}
func C() {}
