package webenum

import (
	"bufio"
	"log"
	http "net/http"
	"os"
	"strconv"
)

func chckstat(target string, ch chan string) {
	resp, _ := http.Get(target)
	if resp.StatusCode != 404 && resp.StatusCode != 301 {
		ch <- target + "\t" + strconv.Itoa(resp.StatusCode)
	}
}

func direnum(target, dire string, ch chan string) {
	resp, _ := http.Get(target + "/" + dire)
	if resp.StatusCode != 404 && resp.StatusCode != 301 {
		ch <- "/" + dire + "\t ->" + " " + strconv.Itoa(resp.StatusCode)
	}
}

func readfile(filename string) []string {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	var lines []string
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	file.Close()
	return lines
}
