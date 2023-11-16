package main

import (
	"flag"

	vt "github.com/mohabgabber/frametst/vt"
)

func main() {
	// mode := os.Args[1]
	//TODO create a command prompt with special commands to make it easier to interact with the tools as the tool gets stuffed with more and more tools (like metasploit)
	vkey := flag.String("vk", "", "Virus Total Api Key")
	level := flag.Int("l", 1, "Level of info retrieved, (1 lowest, 3 highest)")
	hash := flag.String("id", "", "SHA-256/SHA-1/MD5 hash of a file")
	flag.Parse()
	vt.Fretriever(*vkey, *hash, *level)
	// if *fbs {
	// 	vt.Filebehavioursummary(vkey, hash)
	// }
}
