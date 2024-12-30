package main

import (
	"github.com/saferwall/pe"
)

func getPEData(path string) (*pe.File, error) {
	pe, err := pe.New(path, &pe.Options{})
	if err != nil {
		return nil, err
	}

	err = pe.Parse()
	if err != nil {
		return nil, err
	}
	return pe, nil
}
