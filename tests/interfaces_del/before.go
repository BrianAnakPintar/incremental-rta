package main

type I interface {
	M()
}

type A struct{}

func (A) M() {

}

func main() {
	var i I = A{}
	i.M()
}
