package main

import (
	"flag"
	"github.com/attwad/nessie"
	"log"
)

var apiURL, username, password, caCertPath, loginFile string
var insecureSkipVerify bool

func init() {
	flag.StringVar(&apiURL, "api_url", "", "")
	flag.StringVar(&username, "username", "", "Username to login with, in production read that from a file, do not set from the command line or it will end up in your history.")
	flag.StringVar(&password, "password", "", "Password that matches the provided username, in production read that from a file, do not set from the command line or it will end up in your history.")
	flag.Parse()
}

func main() {
	nessus, err := nessie.NewInsecureNessus(apiURL)
	if err != nil {
		panic(err)
	}
	nessus.Verbose = true

	if err := nessus.Login(username, password); err != nil {
		log.Println(err)
		return
	}
	log.Println("Logged-in")
	defer nessus.Logout()
}
