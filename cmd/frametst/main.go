package main

import (
	"fmt"
	"runtime"
	"strings"

	"os"
	"os/exec"

	prom "github.com/Songmu/prompter"
	mng "github.com/mohabgabber/frametst/shellmng"
	vt "github.com/mohabgabber/frametst/vt"
)

type Shell struct {
	Path string
}

func main() {
	var s Shell
	for {
		p := strings.TrimSpace(prom.Prompt("#"+s.Path+">", ""))
		if p != "" {

			if s.Path == "" || p == "back" || p == "clear" || p == "exit" {
				switch p {
				case "help":
					mng.HelpMenu()
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
					fmt.Println("Entered virus total mode")
					fmt.Println("USAGE: file [LEVEL 1-3] [FILE HASH]")
					fmt.Println("Type 'help' for more info")
					s.Path = "vt"
				}
			} else if s.Path == "config" {
				mng.Configmng(p)
			} else if s.Path == "vt" {
				vt.Mng(p)
			}
		}

	}
}
