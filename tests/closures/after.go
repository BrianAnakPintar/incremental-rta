package main

func main() {
	x := func() {}
	x()
	callAnon(func() {})
}

func callAnon(f func()) { f() }
