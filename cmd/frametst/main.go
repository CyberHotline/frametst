package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	prom "github.com/Songmu/prompter"
)

type Shell struct {
	Path string
}

func shell() {
	var s Shell
	for {
		p := strings.TrimSpace(prom.Prompt("#"+s.Path+">", ""))
		if p != "" {
			if s.Path == "" || p == "back" || p == "clear" || p == "exit" {
				switch p {
				case "help":
					HelpMenu()
				case "exit":
					fmt.Println("Will miss you :(")
					os.Exit(0)
				case "clear":
					if runtime.GOOS == "windows" {
						c := exec.Command("cmd", "/c", "cls")
						c.Stdout = os.Stdout
						c.Run()
					} else if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
						c := exec.Command("clear")
						c.Stdout = os.Stdout
						c.Run()
					}
				case "config":
					fmt.Println("Entered config mode. type 'back' to return to normal mode, 'help' for more info")
					s.Path = "config"
				case "back":
					fmt.Println("Back to normal mode")
					s.Path = ""
				case "vt":
					fmt.Println("Entered Virus Total mode")
					fmt.Println("Type 'help' for more info")
					s.Path = "vt"
				case "ha":
					fmt.Println("Entered Hybrid Analysis mode")
					fmt.Println("Type 'help' for more info")
					s.Path = "ha"
				case "mb":
					fmt.Println("Entered Malware Bazaar mode")
					fmt.Println("Type 'help' for more info")
					s.Path = "mb"
				}

			} else if s.Path == "config" {
				Configmng(p)
			} // else if s.Path == "vt" {
			// 	api.Mng(p)
			// } else if s.Path == "ha" {
			// 	api.Mng(p)
			// } else if s.Path == "mb" {
			// 	api.Mng(p)
			// }
		}
	}
}
func main() {
	shell()
}
