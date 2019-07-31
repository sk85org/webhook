package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
)

type Hook struct {
	Path         string `json:"path"`
	Name         string `json:"name"`
	Shell      	 string `json:"shell"`
	Command      string `json:"execute-command"`
	Commanddir   string `json:"execute-command-directry"`
	Xgithubevent string `json:"X-GitHub-Event"`
	Method       string `json:"method"`
	Secret       string `json:"secret"`
}

var (
	file = flag.String("f", "hook.json", "hook configuration file")
	port = flag.String("p", ":8080", "server working port")
)

func main() {

	flag.Parse()

	bytes, err := ioutil.ReadFile(*file)
	if err != nil {
		log.Fatal(err)
	}
	var Hooks []Hook
	if err := json.Unmarshal(bytes, &Hooks); err != nil {
		log.Fatal(err)
	}

	for _, p := range Hooks {
		http.HandleFunc(p.Path, addhandler(p))
	}
	fmt.Println("server starting...")
	err = http.ListenAndServe(*port, nil)
	if err != nil {
		log.Fatal(err)
	}
}

func addhandler(hook Hook) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		event := r.Header.Get("X-GitHub-Event")
		signature := r.Header.Get("X-Hub-Signature")
		body, _ := ioutil.ReadAll(r.Body)

		if auth(hook.Secret, signature, body) && event == hook.Xgithubevent {
			err := os.Chdir(hook.Commanddir)
			if err != nil {
				fmt.Println(err)
			}

			out, err := exec.Command(hook.Shell, hook.Command).Output()
			if err != nil {
				fmt.Println(err)
			}
			fmt.Println(string(out))
		}

	}
}

func auth(secret string, signature string, body []byte) bool {

	decodedsignature := make([]byte, 20)

	hex.Decode(decodedsignature, []byte(signature[5:]))
	secretbyte := []byte(secret)

	computed := hmac.New(sha1.New, secretbyte)
	computed.Write(body)
	return hmac.Equal(computed.Sum(nil), decodedsignature)
}
