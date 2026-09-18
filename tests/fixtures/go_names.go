package main

//go:noinline
func addNumbers(left, right int) int { return left + right }

func main() { println(addNumbers(2, 3)) }
