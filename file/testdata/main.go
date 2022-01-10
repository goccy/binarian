package main

import (
	"fmt"
)

type Iface interface {
	F(int) string
}

func f(v Iface) {
	fmt.Println("func f", v.F(10))
}

type T struct{}

func (*T) F(v int) string {
	return fmt.Sprint(v)
}

func main() {
	f(&T{})
}
