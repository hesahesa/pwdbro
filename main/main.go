package main

import (
	"fmt"

	"github.com/hesahesa/pwdbro"
)

func main() {
	// this is the example usages of pwdbro

	pwdbro := pwdbro.NewDefaultPwdBro()
	status, _ := pwdbro.RunParallelChecks("password")
	for _, resp := range status {
		fmt.Println("=======")
		fmt.Println(resp.Safe)
		fmt.Println(resp.Method)
		fmt.Println(resp.Message)
		fmt.Println(resp.Error)
	}
}
