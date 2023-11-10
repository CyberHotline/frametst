package main

import (
	"flag"

	vt "github.com/mohabgabber/frametst/vt"
)

func main() {
	key := flag.String("vk", "", "Virus Total Api Key")
	hash := flag.String("h", "", "SHA-256/SHA-1/MD5 hash of a file")
	flag.Parse()
	vt.Fileinfo(key, hash)
}
