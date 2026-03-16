package utils

import (
	"fmt"
	"os"
)

func OpenFile(file string) *os.File {
	f, err := os.Open(file)
	if err != nil {
		fmt.Println(err)
		panic("Error opening file")
	}
	return f
}

func OpenFileTrunc(file string) *os.File {
	f, err := os.OpenFile(file, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println(err)
		panic("Error opening file")
	}
	return f
}

