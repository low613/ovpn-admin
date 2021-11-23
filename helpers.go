package main

import (
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"time"
)

func parseDate(layout,datetime string) time.Time {
	t, err := time.Parse(layout, datetime)
	if err != nil {
		log.Println(err)
	}
	return t
}

func parseDateToString(layout,datetime,format string) string {
	return parseDate(layout, datetime).Format(format)
}

func parseDateToUnix(layout,datetime string) int64 {
	return parseDate(layout, datetime).Unix()
}

func runBash(script string) string {
	if *debug {
		log.Println(script)
	}
	cmd := exec.Command("bash", "-c", script)
	stdout, err := cmd.CombinedOutput()
	if err != nil {
		return (fmt.Sprint(err) + " : " + string(stdout))
	}
	return string(stdout)
}

func fExist(path string) bool {
	var _, err = os.Stat(path)

	if os.IsNotExist(err) {
		return false
	} else if err != nil {
		log.Fatal(err)
		return false
	}

	return true
}

func fRead(path string) string {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}

	return string(content)
}

func fCreate(path string) bool {
	var _, err = os.Stat(path)
	if os.IsNotExist(err) {
		var file, err = os.Create(path)
		if err != nil {
			log.Println(err)
			return false
		}
		defer file.Close()
	}
	return true
}

func fWrite(path, content string) {
	err := ioutil.WriteFile(path, []byte(content), 0644)
	if err != nil {
		log.Fatal(err)
	}
}

func fDelete(path string) {
	err := os.Remove(path)
	if err != nil {
		log.Fatal(err)
	}
}

func fDownload(path, url string, basicAuth bool) error {
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if basicAuth {
		req.SetBasicAuth(*masterBasicAuthUser, *masterBasicAuthPassword)
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		log.Printf("WARNING: Download file operation for url %s finished with status code %d\n", url, resp.StatusCode  )
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	fCreate(path)
	fWrite(path, string(body))

	return nil
}

// Basic auth comparing sha256sum of password\
func basicAuth(user, password string) bool {
	// get sha256sum of password
	h := sha256.New()
	h.Write([]byte(password))
	sha256sum := fmt.Sprintf("%x", h.Sum(nil))
	if *masterBasicAuthUser == user && *masterBasicAuthPasswordHash == sha256sum {
		return true
	}
	return false
}

// Basic auth handler comparing sha256sum of password passes through to HandlerFunc
func basicAuthHandler(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if !ok || !basicAuth(user, password) {
			w.Header().Set("WWW-Authenticate", "Basic realm=Restricted")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		handler(w, r)
	}
}
