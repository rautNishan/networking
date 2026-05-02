package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("HANDLER HIT")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "hello world")
	})

	fmt.Println("Starting server...")
	err := http.ListenAndServe("0.0.0.0:3000", nil)
	if err != nil {
		fmt.Println("Error:", err)
	}
}
