package main

func main() {
	A()
}

func A() {
	B()
	C()
}

func B() {

}

func C() {
	D()
}

func D() {
	C()
}
