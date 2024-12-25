package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/garethjensen/amsi"
)

type AMSI struct {
	Path   string
	Bin    []byte
	Size   uint64
	Threat Threat
}

func (a *AMSI) Init(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return errors.New("file not found")
	}
	a.Path = path
	var err error
	a.Bin, err = os.ReadFile(path)
	if err != nil {
		return err
	}
	a.Size = uint64(len(a.Bin))
	return nil
}

func (a *AMSI) Scan(low, high uint64) (threat Threat, err error) {
	err = amsi.Initialize()
	if err != nil {
		return threat, err
	}
	defer amsi.Uninitialize()

	session := amsi.OpenSession()
	defer amsi.CloseSession(session)

	result := session.ScanBuffer(a.Bin[low:high])
	if result == amsi.ResultDetected {
		threat = Threat{
			Name:          "AMSI:Generic",
			Scanner:       "AMSI",
			Source:        a.Path,
			ReferencePath: "https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-antivirus/detect-malicious-software-windows-defender-antivirus",
			Low:           fmt.Sprintf("%08X", low),
			Bytes:         HexDump(low, a.Bin[low:high]),
		}
		a.Threat = threat
		return threat, nil
	}
	return threat, nil
}

func (a *AMSI) ScanAndSplit() error {
	result, err := a.Scan(0, a.Size)
	if err != nil {
		return err
	}
	// result.Print()

	// if threat is found, split the file in half and scan each half
	if result.Name != "" { // Threat Found
		var lastGood uint64 = 0 // lower range
		upperBound := a.Size    // upper range
		mid := upperBound / 2   // pivot point

		// TODO: This could be faster if we scan bottom and top simlutaneously
		// binary search the file
		for upperBound-lastGood > 1 {
			// log.Printf("Splitting %s at 0x%08X", a.Path, mid)
			result, err := a.Scan(lastGood, mid)
			if err != nil {
				return err
			}
			// result.Print()
			// if scan comes back empty abort

			if result.Name != "" { // Threat Found
				upperBound = mid
			} else {
				lastGood = mid
			}

			mid = (upperBound + lastGood) / 2
		}
	}
	return nil
}
