package main

import (
	"fmt"

	"github.com/hesahesa/pwdbro"
)

func main() {
	pwdbro := pwdbro.NewDefaultPwdBro()
	status, _ := pwdbro.RunChecks("wrewtjsdvou30irpfwefi0")
	fmt.Println(status[0], status[1], status[2])
}
