package main

import (
	"fmt"

	"github.com/hesahesa/pwdbro"
)

func main() {
	pwdbro := pwdbro.NewDefaultPwdBro()
	status, _ := pwdbro.RunChecks("")
	fmt.Println(status[0], status[1])
}
