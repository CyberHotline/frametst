package mb

import (
	"fmt"
	"strings"
)

// TODO: To Implement Later
func Mng(order string) {
	sliced := strings.Split(order, " ")
	if sliced[0] == "help" {
		fmt.Println("USAGE of hybrid analysis module:")
		fmt.Println("\thelp\tPrint help menu")
		fmt.Println("\tfile [LEVEL 1-3] [HASH]\tRetrieve a file report")
	} else if sliced[0] == "file" {
		fmt.Println(string("hello"))
	}
}
