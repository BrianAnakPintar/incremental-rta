package main

func main() {
	recursive(0)
}

func recursive(n int) {
	if n < 3 {
		recursive(n + 1)
	}
}
