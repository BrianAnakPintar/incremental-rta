package main

import "fmt"

func main() {
	Foo()
}

func Foo() {
	fmt.Println("foo")
	Bar()
}

func Bar() {
	fmt.Println("bar")
}
