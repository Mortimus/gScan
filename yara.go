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
	"sync"
)

var maxThreads int = 50
var maxHex uint64 = 128

var yaraPath string = "./tools/yara64.exe"
var yaraCompilerPath string = "./tools/yarac64.exe"

var rulesPath string = "./rules/compiled"

type Yara struct {
	sync.Mutex
	Path        string
	RulesPath   string
	Rules       []string
	Bin         []byte
	Size        uint64
	Threats     []Threat
	ScanProcess bool
}

func init() {
	// register as a scanner
	var yara = &Yara{}
	scanners = append(scanners, yara)
}

func (y *Yara) GetThreats() []Threat {
	return y.Threats
}

func (t *Threat) Print() {
	//TODO: Colorize the output
	fmt.Printf("Threat: %s\n", t.Name)
	// print low as hex
	fmt.Printf("Bad Bytes Offset: %s\n", t.Low)
	// print the bad bytes as a standard hex dump with associated ASCII
	fmt.Printf("%s\n", t.Bytes)
}

func RuleToString(compiledPath string) (string, error) {
	tar, err := compiledToRule(compiledPath)
	if err != nil {
		return "", err
	}
	rule, err := os.ReadFile(tar)
	if err != nil {
		return "", err
	}
	return string(rule), nil
}

func compiledToRule(compiledPath string) (string, error) {
	// get the rule name from the path
	// remove the path and extension
	// return the rule name
	sourceFiles := ".yar"    // Yara file
	compiledFiles := ".yarc" // Compiled Yara file
	sourcePath := "source"
	compilePath := "compiled"
	// ensure compiledPath is an absolute path
	compiledPath, err := filepath.Abs(compiledPath)
	if err != nil {
		return "", err
	}
	tar := strings.Replace(compiledPath, compiledFiles, sourceFiles, 1)
	// modify path ./rules/source -> ./rules/compiled
	tar = strings.Replace(tar, compilePath, sourcePath, 1)
	return tar, nil
}

func (y *Yara) Name() string {
	return "Yara"
}

func (y *Yara) Init(path string) error {
	var err error
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return errors.New("file not found")
	}
	y.Path = path
	y.RulesPath = rulesPath
	y.Rules = []string{}
	err = y.LoadCompiledRules()
	if err != nil {
		return err
	}
	y.Bin, err = os.ReadFile(path)
	if err != nil {
		return err
	}
	y.Size = uint64(len(y.Bin))
	return nil
}

func (y *Yara) Cleanup() {
	// Nothing to cleanup
}

func (y *Yara) LoadCompiledRules() error {
	// load rules from the rulesPath into the rules slice
	// walk rulesPath and load each .yar file into the rules slice
	compiledFiles := ".yarc"
	// log.Printf("Loading yara rules from %s\n", y.RulesPath)

	err := filepath.WalkDir(y.RulesPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// fmt.Printf("Checking %s with extention %s\n", path, filepath.Ext(path))
		if !d.IsDir() && filepath.Ext(path) == compiledFiles {
			absPath, err := filepath.Abs(path)
			if err != nil {
				return err
			}
			y.Rules = append(y.Rules, absPath)
		}
		return nil
	})
	if len(y.Rules) == 0 {
		return errors.New("no compiles Yara rules found")
	}

	return err
}

func compileRules(sourcePath, compilePath string) error {
	// load rules from the rulesPath into the rules slice
	// walk rulesPath and load each .yar file into the rules slice
	sourceFiles := ".yar"    // Yara file
	compiledFiles := ".yarc" // Compiled Yara file
	// log.Printf("Loading yara rules from %s\n", y.RulesPath)

	err := filepath.WalkDir(sourcePath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && (filepath.Ext(path) == sourceFiles) {
			dest := strings.Replace(path, sourceFiles, compiledFiles, 1)
			// modify path ./rules/source -> ./rules/compiled
			dest = strings.Replace(dest, sourcePath, compilePath, 1)
			if _, err := os.Stat(dest); os.IsNotExist(err) {
				// Make missing folders
				tarFolder := filepath.Dir(dest)
				err := os.MkdirAll(tarFolder, os.ModePerm)
				if err != nil {
					return err
				}
				fmt.Printf("Compiling %s to %s\n", path, dest)
				compileRule(path, dest)
			}
		}
		return nil
	})
	return err
}

func compileRule(source, dest string) {
	cmd := exec.Command(yaraCompilerPath, source, dest)
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	cmd.Run()
	// stdOut := out.String()
	// stdErr := stderr.String()
}

func yaraOutputToThreat(output, rule, fullpath string, low, high uint64, data []byte) (Threat, error) {
	// fmt.Printf("Threat found in %s with rule %s: %s\n", fullpath, rule, stdOut)
	// split output on newline
	// get the first line
	outs := strings.Split(output, "\n")

	// remove fullpath from stdOut
	threatLength := len(outs[0]) - len(fullpath) - 3
	if threatLength <= 0 {
		threatLength = len(outs[0])
	}
	threatname := outs[0][:threatLength]
	// get source rule
	ref, err := RuleToString(rule)
	if err != nil {
		return Threat{}, err
		// fmt.Printf("Error getting rule: %s\n", err)
		// return threat, err
	}
	refPath, err := compiledToRule(rule)
	if err != nil {
		return Threat{}, err
		// return threat, err
	}
	var hexTarget uint64
	if len(outs[1]) > 0 {
		hexTarget, err = hexLookup(outs[1])
		if err != nil {
			return Threat{}, err
		}
	}
	hexEnd := high
	if (hexEnd - hexTarget) > maxHex {
		hexEnd = hexTarget + maxHex
	}
	threat := Threat{
		Name:          threatname,
		Scanner:       "Yara",
		Source:        fullpath,
		Reference:     ref,
		ReferencePath: refPath,
		Low:           fmt.Sprintf("%08X", low),
		Bytes:         HexDump(hexTarget, data[hexTarget:hexEnd]),
	}
	return threat, nil
}

func hexLookup(tar string) (uint64, error) {
	// 0x20e:$a_63_3: 6D
	// split on :
	// get the first element
	split := strings.Split(tar, ":")
	// get the first element
	// remove the 0x
	offset := split[0][2:]
	// convert to uint64
	// fmt.Printf("Offset: %s\n", offset)
	return hexToUint64(offset)
}

func (y *Yara) Scan(low, high uint64) (threat Threat, err error) {
	// Defender demands absolute paths
	fullpath, err := filepath.Abs(y.Path)
	if err != nil {
		return threat, err
	}
	// TODO: lookup the yara binary path
	// yaraPath := "./tools/yara64.exe"
	// loop through all y.rules and scan the file
	log.Printf("Scanning %s with %d Yara rules\n", fullpath, len(y.Rules))
	var sem = make(chan int, maxThreads)
	chanErrors := make(chan error)
	for _, rule := range y.Rules { // TODO: Add concurrency
		sem <- 1
		go func() { // we need to add an errors channel
			// fmt.Printf("Scanning %s with %s\n", fullpath, rule)
			// Only using compiled rules
			// string extract
			// no warnings
			cmd := exec.Command(yaraPath, "-C", "-s", "-w", rule, fullpath)
			var out, stderr bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = &stderr

			cmd.Run()
			stdOut := out.String()
			// stdErr := stderr.String()
			// fmt.Printf("Scan Result for %s: %s\nErrors: %s", rule, stdOut, stdErr)
			if stdOut != "" {
				threat, err = yaraOutputToThreat(stdOut, rule, fullpath, low, high, y.Bin)
				if err != nil {
					chanErrors <- err
					return
				}
				y.Lock() // Avoid concurrency issues
				defer y.Unlock()
				y.Threats = append(y.Threats, threat)
				// fmt.Printf("Found threat, exiting\n")
				// return threat, nil
			}
			<-sem
		}()
	}
	close(chanErrors)
	for err := range chanErrors {
		fmt.Printf("Error scanning %s: %s\n", y.Path, err)
		// return threat, err
	}
	// stdOut := out.String()
	// stdErr := stderr.String()
	// if stdErr != "" {
	// 	return threat, errors.New(stdErr)
	// }
	// // fmt.Printf("Scan Result for %s: %s\nErrors: %s", file.Name(), stdOut, stderr.String())

	// if strings.Contains(stdOut, "Threat  ") {
	// 	threat = Threat{
	// 		Name:  extractThreat(stdOut),
	// 		Low:   low,
	// 		High:  high,
	// 		bytes: d.Bin[low:high],
	// 	}
	// 	d.Threat = threat
	// 	// log.Printf("Saving threat %#+v\n", threat)
	// 	return threat, nil
	// }

	return threat, nil
}

func (y *Yara) ScanAndSplit() error {
	// No need to split, just scan the file
	_, err := y.Scan(0, y.Size)
	return err
}
