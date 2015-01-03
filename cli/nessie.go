// Package main implements a test client that starts a scan, wait until it finishes and exports its results to a csv file.
package main

import (
	"flag"
	"github.com/attwad/nessie"
	"io/ioutil"
	"log"
	"strings"
	"time"
)

var apiURL, username, password string

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

	if err := nessus.Login(username, password); err != nil {
		log.Println(err)
		return
	}
	log.Println("Logged-in")

	var scanID int64 = 13
	// We only care about the last scan, so no use for the scan UUID here.
	if _, err = nessus.StartScan(scanID); err != nil {
		panic(err)
	}
	for {
		details, err := nessus.ScanDetails(scanID)
		if err != nil {
			panic(err)
		}
		if strings.ToLower(details.Info.Status) == "completed" {
			log.Println("Scan completed")
			break
		}
		log.Println("Scan is", details.Info.Status)
		time.Sleep(5 * time.Second)
	}

	exportID, err := nessus.ExportScan(scanID, nessie.ExportCSV)
	if err != nil {
		panic(err)
	}
	for {
		if finished, err := nessus.ExportFinished(scanID, exportID); err != nil {
			panic(err)
		} else if finished {
			log.Println("Scan export finished")
			break
		}
		log.Println("Scan export ongoing...")
		time.Sleep(5 * time.Second)
	}
	csv, err := nessus.DownloadExport(scanID, exportID)
	if err != nil {
		panic(err)
	}
	if err := ioutil.WriteFile("report.csv", csv, 0600); err != nil {
		panic(err)
	}

	defer nessus.Logout()
}
