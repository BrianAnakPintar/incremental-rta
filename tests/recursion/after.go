package main

func main() {
	recursive(0)
}

func recursive(n int) {
	if n < 3 {
		baz()
	}
}

func baz() {
}
