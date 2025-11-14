package main

type I interface {
	M()
}

type A struct{}

func (A) M() {}

type B struct{}

func (B) M() {}

func main() {
	var i I = A{}
	i.M()

	i = B{}
}
