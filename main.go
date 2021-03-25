package main

import "github.com/tcfw/ocs/cdi"

func main() {
	s := cdi.NewServer()
	err := s.Start()
	if err != nil {
		panic(err)
	}

	select {}
}
