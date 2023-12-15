package ha

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	ur "net/url"
	"strings"

	mng "github.com/mohabgabber/frametst/shellmng"
)

var BASEURL string = "https://hybrid-analysis.com/api/v2/"

func Fretriever(key, hash string) []byte {
	url := BASEURL + "search/hash"

	data := ur.Values{}
	data.Add("hash", hash)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(data.Encode())))
	if err != nil {
		log.Println(err)
	}
	req.Header.Add("api-key", key)
	req.Header.Add("accept", "application/json")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Println(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
	}
	return body
}

func Mng(order string) {
	sliced := strings.Split(order, " ")
	if sliced[0] == "help" {
		fmt.Println("USAGE of hybrid analysis module:")
		fmt.Println("\thelp\tPrint help menu")
		fmt.Println("\tfile [LEVEL 1-3] [HASH]\tRetrieve a file report")
	} else if sliced[0] == "file" {
		fmt.Println(string(Fretriever(mng.Q.HybridAnalysis, sliced[2])))
	}
}
