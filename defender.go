package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

var defenderPath string

func init() {
	var err error
	defenderPath, err = FindDefenderCli()
	if err != nil {
		log.Fatal("Error:", err)
	}
	// register as a scanner
	var defender = &Defender{}
	scanners = append(scanners, defender)
}

// Check if folder is whitelisted at HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths
// check the registry HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths
// if folder is in the list, return true
// else return false
// Requires admin privileges
func isWhitelisted(folder string) (bool, error) {
	dir, err := os.Getwd()
	if err != nil {
		return false, err
	}

	keyPath := `SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths`
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.QUERY_VALUE)
	if err != nil {
		// if access denied report so
		return false, err
	} else {
		// fmt.Println("Key exists")
		// enumerate the keys
		keys, err := key.ReadValueNames(-1)
		if err != nil {
			return false, err
		}
		for _, k := range keys {
			// log.Println(k)
			if k == folder { // detonate folder
				return true, err
			}
			if k == dir { // check if running folder is whitelisted as well
				return true, err
			}
		}

		key.Close()
	}

	return false, nil
}

// FindDefenderCli returns the MpCMDRun.exe path from registry
func FindDefenderCli() (string, error) {
	keyPath := `SOFTWARE\Microsoft\Windows Defender`
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer key.Close()
	// get the value of the key
	val, _, err := key.GetStringValue("InstallLocation")
	if err != nil {
		return "", err
	}
	return filepath.Join(val, "MpCmdRun.exe"), nil
}

type Defender struct {
	Path       string
	Bin        []byte
	Size       uint64
	TempFolder string
	Threat     Threat
}

func (d Defender) Name() string {
	return "Microsoft Defender"
}

func (d *Defender) GetThreats() []Threat {
	return []Threat{d.Threat}
}

func (d *Defender) Init(path string) error {
	log.Printf("Scanning %s with %s\n", path, d.Name())
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return errors.New("file not found")
	}
	d.Path = path
	var err error
	// loop until file is not in use
	for {
		d.Bin, err = os.ReadFile(path)
		if err != nil {
			if strings.Contains(err.Error(), "used by another process") {
				log.Println("File in use, retrying in 1 second")
				// wait 1 second
				time.Sleep(1 * time.Second)
				// unset err
				err = nil
				continue
			} else {
				return err
			}
		} else {
			break
		}
	}
	d.Size = uint64(len(d.Bin))
	d.TempFolder, err = os.MkdirTemp(".", "malware")
	if err != nil {
		return err
	}
	return nil
}

func (d Defender) Cleanup() {
	// log.Printf("Cleaning up %s", d.TempFolder)
	err := os.RemoveAll(d.TempFolder)
	if err != nil {
		// convert to patherror

		log.Printf("Error cleaning up %s: %s", d.TempFolder, err)
	}
}

// Scan with Defender
func (d *Defender) Scan(low, high uint64) (threat Threat, err error) {
	// log.Printf("Scanning %s from 0x%08X to 0x%08X", d.Path, low, high)
	// write bytes to a file in the temp folder
	file, err := os.CreateTemp(d.TempFolder, "malicious")
	if err != nil {
		return threat, err
	}
	// log.Printf("Created temporary file %s", file.Name())
	defer file.Close()
	defer os.Remove(file.Name())
	// write the testing bytes to the temporary file
	err = os.WriteFile(file.Name(), d.Bin[low:high], 0644)
	if err != nil {
		return threat, err
	}
	// Defender demands absolute paths
	fullpath, err := filepath.Abs(file.Name())
	if err != nil {
		return threat, err
	}
	cmd := exec.Command(defenderPath, "-Scan", "-ScanType", "3", "-File", fullpath, "-DisableRemediation", "-Trace", "-Level", "0x10")
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	cmd.Run()

	stdOut := out.String()
	stdErr := stderr.String()
	if stdErr != "" {
		return threat, errors.New(stdErr)
	}
	// fmt.Printf("Scan Result for %s: %s\nErrors: %s", file.Name(), stdOut, stderr.String())

	if strings.Contains(stdOut, "Threat  ") {
		threat = Threat{
			Name:          extractThreat(stdOut),
			Scanner:       "Microsoft Defender",
			Source:        d.Path,
			ReferencePath: "https://www.microsoft.com/en-us/wdsi/definitions",
			Low:           fmt.Sprintf("%08X", low),
			Bytes:         HexDump(low, d.Bin[low:high]),
		}
		d.Threat = threat
		// log.Printf("Saving threat %#+v\n", threat)
		return threat, nil
	}

	return threat, nil
}

// Ripped from gocheck
func extractThreat(scanOutput string) string {
	lines := strings.Split(scanOutput, "\n")
	threatInfo := ""

	for _, line := range lines {
		if strings.HasPrefix(line, "Threat ") {
			threatInfo = line
			break
		}
	}

	if threatInfo != "" {

		threatInfo = strings.Split(threatInfo, ": ")[1]
		return threatInfo
	}

	return "No specific threat information found"
}

func (d *Defender) ScanAndSplit() error {
	result, err := d.Scan(0, d.Size)
	if err != nil {
		return err
	}
	// result.Print()

	// if threat is found, split the file in half and scan each half
	if result.Name != "" { // Threat Found
		var lastGood uint64 = 0 // lower range
		upperBound := d.Size    // upper range
		mid := upperBound / 2   // pivot point

		// TODO: This could be faster if we scan bottom and top simlutaneously
		// binary search the file
		for upperBound-lastGood > 1 {
			// log.Printf("Splitting %s at 0x%08X", d.Path, mid)
			result, err := d.Scan(lastGood, mid)
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
