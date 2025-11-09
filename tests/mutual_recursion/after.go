package main

func main() {
	A()
}

func A() {
	B()
}

func B() {

}

func C() {
	D()
}

func D() {
	C()
}
