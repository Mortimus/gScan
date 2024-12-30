package main

// TODO: Add logging to logs folder

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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/saferwall/pe"
	"golang.org/x/sys/windows/registry"
)

// Folder that is whitelisted and monitored for new files
var detonateFolder string = "./detonate"
var scanners []Scanner

func main() {
	var compileYaraRules bool
	// using the flag package to parse command line arguments
	// select the folder to monitor
	flag.StringVar(&detonateFolder, "d", "./detonate", "Folder that is whitelisted and monitored for new files")
	// set the max number of threads
	flag.IntVar(&maxThreads, "t", 50, "Max number of threads to use")
	// should we compile the yara rules
	flag.BoolVar(&compileYaraRules, "c", false, "Compile Yara rules")
	flag.Parse()
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
						log.Println("Error scanning file:", err)
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
	for _, scanner := range scanners {
		start := time.Now()
		err = scanner.Init(m.Path)
		if err != nil {
			log.Printf("Error initializing %s: %s", scanner.Name(), err)
			continue
		}
		err = scanner.ScanAndSplit()
		if err != nil {
			fmt.Printf("Error scanning %s: %s\n", scanner.Name(), err)
			continue
		}
		for _, threat := range scanner.GetThreats() {
			if threat.Name != "" { // Threat Found
				m.Malicious = true
				// scanner.Threat.Print()
				threats = append(threats, threat)
			}
		}
		scanner.Cleanup() // dont defer since we want to cleanup right after a scanner finishes
		elapsed := time.Since(start)
		log.Printf("%s scan took %s", scanner.Name(), elapsed)
	}

	// Generate report
	if len(threats) > 0 {
		fmt.Printf("Generating report for %s\n", m.Path)
		// get extension
		extension := filepath.Ext(m.Path)
		var pedata *pe.File
		// get pe data if it is an exe or dll
		if extension == ".exe" || extension == ".dll" {
			pedata, err = getPEData(m.Path)
			if err != nil {
				return err
			}
		}
		err = GenerateMarkdown(pedata, threats...)
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
	Sha256   string
	FileSize string
	Date     string
	PeData   *pe.File
	Threats  []Threat
}

type Threat struct {
	Name          string
	Scanner       string
	Source        string
	Reference     string
	ReferenceName string
	ReferencePath string
	Low           string // uint64 to hex string
	Bytes         string // hex.dump of []byte
}

type Scanner interface {
	Init(path string) error
	Cleanup()
	Scan(low, high uint64) (Threat, error)
	ScanAndSplit() error
	GetThreats() []Threat
	Name() string
}

// GenerateMarkdown creates a markdown file using a template from a file.
func GenerateMarkdown(pedata *pe.File, threats ...Threat) error {
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
	// get sha256 of path
	// read source into memory
	bin, err := os.ReadFile(threats[0].Source)
	if err != nil {
		return err
	}
	sha256 := sha256.Sum256(bin)
	// get file size
	fileInfo, err := os.Stat(threats[0].Source)
	if err != nil {
		return err
	}
	fileSize := strconv.FormatInt(fileInfo.Size(), 10)
	// Create the data to pass to the template
	path := strings.ReplaceAll(threats[0].Source, "\\", "/")
	data := MarkdownData{
		Filename: filepath.Base(threats[0].Source),
		Path:     path,
		Sha256:   fmt.Sprintf("%x", sha256),
		FileSize: fileSize,
		Date:     time.Now().Format("2006-01-02 15:04:05"),
		PeData:   pedata,
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
