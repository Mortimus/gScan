package main

// Objectives
// Check if detonate folder is whitelisted by defender
// monitor detonate folder for new files
// if new file is detected, scan it with gocheck
// if file is malicious, create a report and store it in the report folder
// if it is not malicious, scan it using yara rules
// if it is malicious, create a report and store it in the report folder
// if it is not malicious run the process and then scan it with yara rules
// if it is malicious, create a report and store it in the report folder
// if it is not malicious, run the process again and use BestEDROnTheMarket to scan it
// if it is malicious, create a report and store it in the report folder

import (
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"golang.org/x/sys/windows/registry"
)

// Folder that is whitelisted and monitored for new files
var detonateFolder string = "./detonate"

func main() {
	var compileYaraRules bool
	compileYaraRules = false
	if compileYaraRules {
		fmt.Printf("Compiling Yara rules...\n")
		// Compile Rules
		absSourcePath, err := filepath.Abs("./rules/source")
		if err != nil {
			log.Fatal("Error:", err)
		}
		absCompiledPath, err := filepath.Abs("./rules/compiled")
		if err != nil {
			log.Fatal("Error:", err)
		}
		err = compileRules(absSourcePath, absCompiledPath)
		if err != nil {
			log.Fatal("Error:", err)
		}
		fmt.Printf("Yara rules compiled\n")
		return
	}
	// Check if detonate folder is whitelisted by defender
	detonatePath, err := filepath.Abs(detonateFolder) // Get the absolute path of the detonate folder

	if err != nil {
		log.Fatal("Error:", err)
	}
	whitelisted, err := isWhitelisted(detonatePath)
	if err != nil {
		if strings.EqualFold(err.Error(), "Access is denied.") {
			log.Println("Cannot read defender whitelist, are you running as admin? Assuming folder is whitelisted and proceeding")
			whitelisted = true
		} else {
			if err == registry.ErrNotExist {
				log.Fatal("Registry key does not exist, is Defender installed?")
			} else {
				log.Fatal("Error:", err)
			}
		}
	}
	if !whitelisted {
		log.Fatal("Detonate folder is not whitelisted by defender")
	}
	// fmt.Printf("Detonate folder is whitelisted by defender\n")
	fmt.Printf("Watching folder: %s\n", detonatePath)

	// monitor detonate folder for new files
	// Create new watcher.
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	// Start listening for events.
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Has(fsnotify.Create) {
					// log.Println("Scanning: ", event.Name)
					// malicious, errs := checkWithGocheck(event.Name)
					malware := Malware{Path: event.Name}
					// sleep for a few seconds to allow the file to be written
					// time.Sleep(2 * time.Second) // TODO: this is bad, we should check if the file is still being written
					err := malware.Scan()
					if err != nil {
						// if error is file in use rescan
						if strings.Contains(err.Error(), "used by another process") {
							// loop until file is not in use sleeping 1 second between checks
							for {
								log.Println("File in use, retrying in 1 second")
								time.Sleep(1 * time.Second)
								err = malware.Scan()
								if err == nil {
									break
								}
							}
						} else {
							// if error scanning file, log it
							log.Println("Error scanning file:", err)
						}
					}
					if malware.Malicious {
						log.Println("Malicious file detected: ", event.Name)
					} else {
						log.Println("File is not malicious: ", event.Name)
					}

				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Println("error:", err)
			}
		}
	}()

	// Add a path.
	err = watcher.Add(detonatePath)
	if err != nil {
		log.Fatal(err)
	}

	// Block main goroutine forever.
	<-make(chan struct{})

}

type Malware struct {
	Path       string
	Malicious  bool
	ReportPath string
}

func (m *Malware) Scan() error {
	// check if file size is > 0 bytes
	// if not, return false, "File is empty", nil
	var threats []Threat

	fileInfo, err := os.Stat(m.Path)
	if err != nil {
		return err
	}

	if fileInfo.Size() == 0 {
		m.Malicious = false
		return errors.New("file is empty")
	}
	// Scan with Defender
	{
		log.Printf("Scanning %s with Windows Defender...", m.Path)
		start := time.Now()
		var defender Defender
		err = defender.Init(m.Path)
		if err != nil {
			return err
		}
		defer defender.Cleanup()
		err = defender.ScanAndSplit()
		if err != nil {
			return err
		}
		if defender.Threat.Name != "" { // Threat Found
			m.Malicious = true
			// defender.Threat.Print()
			threats = append(threats, defender.Threat)
		}
		elapsed := time.Since(start)
		log.Printf("Scan took %s", elapsed)
	}
	// Scan with AMSI
	{
		log.Printf("Scanning %s with AMSI...", m.Path)
		start := time.Now()
		var amsi AMSI
		err = amsi.Init(m.Path)
		if err != nil {
			return err
		}
		err = amsi.ScanAndSplit()
		if err != nil {
			return err
		}
		if amsi.Threat.Name != "" { // Threat Found
			m.Malicious = true
			// amsi.Threat.Print()
			threats = append(threats, amsi.Threat)
		}
		elapsed := time.Since(start)
		log.Printf("Scan took %s", elapsed)
	}
	// Scan with Yara static file
	{
		// log.Printf("Scanning %s with Yara rules...", m.Path)
		start := time.Now()
		var yara Yara
		err = yara.Init(m.Path, "./rules/compiled")
		if err != nil {
			return err
		}
		defer yara.Cleanup()
		err = yara.ScanAndSplit()
		if err != nil {
			return err
		}
		for _, threat := range yara.Threats {
			if threat.Name != "" { // Threat Found
				m.Malicious = true
				// yara.Threat.Print()
				threats = append(threats, threat)
			}
		}
		elapsed := time.Since(start)
		log.Printf("Scan took %s", elapsed)
	}
	// start PCAP capture
	// start Eventlogs capture
	// start Registry capture
	// start common directories capture

	// Scan with Yara running process

	// Scan with BestEDROnTheMarket

	// Scan pcap file

	// Scan EventLogs

	// Scan Registry

	// Scan common directories

	// Generate report
	if len(threats) > 0 {
		fmt.Printf("Generating report for %s\n", m.Path)
		err = GenerateMarkdown(threats...)
		if err != nil {
			fmt.Printf("Error generating report: %s\n", err)
			return err
		}
	}

	return nil
}

type MarkdownData struct {
	Filename string
	Path     string
	Threats  []Threat
}

type Threat struct {
	Name          string
	Scanner       string
	Source        string
	Reference     string
	ReferencePath string
	Low           string // uint64 to hex string
	Bytes         string // hex.dump of []byte
}

type Scanner interface {
	Init(path string) error
	Cleanup()
	Scan(low, high uint64) (Threat, error)
	ScanAndSplit() error
}

// GenerateMarkdown creates a markdown file using a template from a file.
func GenerateMarkdown(threats ...Threat) error {
	templateFile := "./templates/report.md"
	// Parse the template from the file
	tmpl, err := template.ParseFiles(templateFile)
	if err != nil {
		return err
	}

	// Create the output file
	// set the output filename to the threat.source but stripping the directories and extension and append the date
	outputFilename := filepath.Base(threats[0].Source)
	outputFilename = strings.TrimSuffix(outputFilename, filepath.Ext(outputFilename))
	outputFilename = fmt.Sprintf("%s-%s.md", outputFilename, time.Now().Format("2006-01-02-15-04-05"))
	outputFilename = filepath.Join("./reports", outputFilename)
	file, err := os.Create(outputFilename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Create the data to pass to the template
	data := MarkdownData{
		Filename: filepath.Base(threats[0].Source),
		Path:     threats[0].Source,
		Threats:  threats,
	}

	// Execute the template with the provided data
	return tmpl.Execute(file, data)
}

func HexDump(low uint64, data []byte) string {
	// get normal hex dump and update the addresses starting with low
	// 00000000  4d 5a 90 00 03 00 00 00  04 00 00 00 ff ff 00 00  |MZ..............|
	// 00000010  b8 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00  |........@.......|
	// should replace 00000000 with low
	// and 00000010 with low+16
	// and so on
	hexString := hex.Dump(data)
	lines := strings.Split(hexString, "\n")
	for i, line := range lines {
		if len(line) < 8 {
			continue
		}
		// get the address
		address := line[:8]
		// convert it to uint64
		addr, err := hexToUint64(address)
		if err != nil {
			return hexString
		}
		// replace it with low
		addr = addr + low
		newAddress := fmt.Sprintf("%08X", addr)
		lines[i] = newAddress + line[8:]
	}
	return strings.Join(lines, "\n")
}

func hexToUint64(data string) (uint64, error) {
	return strconv.ParseUint(data, 16, 64)
}
