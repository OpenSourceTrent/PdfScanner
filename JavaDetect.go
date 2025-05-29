package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

func SandBox() {

}

func MatchesThreatScore(Path string, TotalMatches uint8) {
	if TotalMatches == 6 {
		fmt.Println(Path)
		fmt.Println("Severity: Critical")
	}
	if TotalMatches == 5 {
		fmt.Println(Path)
		fmt.Println("Severity: High")
	}
	if TotalMatches > 2 && TotalMatches < 5 {
		fmt.Println(Path)
		fmt.Println("Severity: Medium")
	}
	if TotalMatches < 2 {
		fmt.Println(Path)
		fmt.Println("Severity: Low")
	}
}

func LogSave(SuspiciousFiles string) {

}

// Function Looks for Javascript and sets true for each match it finds
func DetectingJavascript(FileData string, Verbose bool) (int16, bool, bool, bool, bool, bool, bool, bool, bool) {
	var TotalMatches int16 = 0
	var JavaMatch bool
	var JSMatch bool
	var AppMatch bool
	var AppHexMatch bool
	var OpenActionMatch bool
	var AAMatch bool
	var ThisMatch bool
	var ThisHexMatch bool

	JavaDone := make(chan bool)
	JSDone := make(chan bool)
	AppDone := make(chan bool)
	AppHexDone := make(chan bool)
	OpenActionDone := make(chan bool)
	AADone := make(chan bool)
	Thisdone := make(chan bool)
	ThisHexDone := make(chan bool)

	//using go routines for quicker file scanning
	go func() {
		JavaString, err := regexp.MatchString("/JavaScript\\s+(\\d+\\s+\\d+\\s+R|\\(.*?\\)|<.*?>)", FileData)
		if err != nil {
			fmt.Println(err.Error())
		}
		if JavaString {
			if Verbose {
				fmt.Println("Found Javascript String!")
			}
			JavaMatch = true
			TotalMatches += 1
		}
		JavaDone <- true
	}()

	go func() {
		JS_String, err := regexp.MatchString("/JS\\s*(\\((.*?)\\)|<([0-9A-Fa-f\\s]*)>)", FileData)
		if err != nil {
			fmt.Println(err.Error())
		}
		if JS_String {
			if Verbose {
				fmt.Println("Found JS String")
			}
			JSMatch = true
			TotalMatches += 1
		}
		JSDone <- true
	}()

	go func() {
		AppString, err := regexp.MatchString("app.", FileData)
		if err != nil {
			fmt.Println(err.Error())
		}
		if AppString {
			if Verbose {
				fmt.Println("Found App. String")
			}
			AppMatch = true
			TotalMatches += 1
		}
		AppDone <- true
	}()

	go func() {
		AppHexValue, err := regexp.MatchString("(6170702e)", FileData)
		if err != nil {
			fmt.Println(err.Error())
		}
		if AppHexValue {
			if Verbose {
				fmt.Println("Found App. String in Hexidecimal")
			}
			AppHexMatch = true
			TotalMatches += 1
		}
		AppHexDone <- true
	}()

	go func() {
		OpenAction, err := regexp.MatchString("/OpenAction\\s+(\\d+\\s+\\d+\\s+R|\\(.*?\\)|<.*?>)", FileData)
		if err != nil {
			fmt.Println(err.Error())
		}
		if OpenAction {
			if Verbose {
				fmt.Println("Found OpenAction String")
			}
			OpenActionMatch = true
			TotalMatches += 1
		}
		OpenActionDone <- true
	}()

	go func() {
		AA_String, err := regexp.MatchString("/AA\\s+(\\d+\\s+\\d+\\s+R)", FileData)
		if err != nil {
			fmt.Println(err.Error())
		}
		if AA_String {
			if Verbose {
				fmt.Println("Found AA String")
			}
			AAMatch = true
			TotalMatches += 1
		}
		AADone <- true
	}()

	go func() {
		ThisString, err := regexp.MatchString("this.", FileData)
		if err != nil {
			fmt.Println(err.Error())
		}
		if ThisString {
			if Verbose {
				fmt.Println("Found this. String")
			}
			ThisMatch = true
			TotalMatches += 1
		}
		Thisdone <- true
	}()

	go func() {
		ThisHexString, err := regexp.MatchString("746869732e", FileData)
		if err != nil {
			fmt.Println(err.Error())
		}
		if ThisHexString {
			if Verbose {
				fmt.Println("Found this. string in hexidecimal")
			}
			ThisHexMatch = true
			TotalMatches += 1
		}
		ThisHexDone <- true
	}()

	//waits for all threads to finish
	<-JavaDone
	<-JSDone
	<-AppDone
	<-AppHexDone
	<-OpenActionDone
	<-AADone
	<-Thisdone
	<-ThisHexDone

	if TotalMatches == 0 {
		if Verbose {
			fmt.Println("**No JavaScript Detected**")
		}
	}
	if Verbose {
		fmt.Println()
	}
	return TotalMatches, JavaMatch, JSMatch, AppMatch, AppHexMatch, OpenActionMatch, AAMatch, ThisMatch, ThisHexMatch
}

func main() {
	StartTime := time.Now()

	//Warning that is displayed for each suspicious pdf at the end of the program. Shows what kind of javascript content was found
	var JavaWarning string = "*/Javascript String was found"
	var JSWarning string = "*/JS String was found"
	var AppWarning string = "*App. String was found"
	var AppHexWarning string = "*App. String in hexidecimal was found"
	var OpenActionWarning string = "*/OpenAction String was found"
	var AAWarning string = "*/AA String was found"
	var ThisWarning string = "*this. String was found"
	var ThisHexWarning string = "*this. String in hexidecimal was found"

	//Variables for Pdfs
	FileMatches := make(map[string]int) //Need for threatscore func
	var TotalSuspect uint16 = 0         //total suspect pdfs
	var TotalClean uint16 = 0           //total clean pdfs
	var TotalPdfs uint16 = 0            //total pdfs scanned
	var TotalFiles uint32 = 0           //total files scanned
	var SuspiciousFiles []string        //List of files with javascript
	var ScanPath string                 //The string needed for the -path option

	//Flags needed for command line options
	VeryVerboseFlag := flag.Bool("vv", false, "Very Verbose Mode (Prints all files, not just .pdf)")
	VerboseFlag := flag.Bool("v", false, "Verbose Mode")
	PathFlag := flag.String("p", ScanPath, "Path to Pdf(s)")
	ThreatScoreFlag := flag.Bool("ts", false, "Shows threat score for each pdf")
	HelpFlag := flag.Bool("h", false, "Shows help page")

	//Custom help page
	flag.Usage = func() {

		//Flag Option strings
		p_Option := "-p"
		ts_Option := "-ts"
		v_Option := "-v"
		vv_Option := "-vv"
		h_Option := "-h"

		//Flag Descriptions
		p := "Path to Pdf(s)"
		ts := "Shows threat score for each pdf"
		v := "Verbose Mode"
		vv := "Very Verbose Mode (Prints all files, not just .pdf)"
		h := "Shows help page"

		//This sets text alignment for the help page
		fmt.Printf("%-10s %10s\n", p_Option, p)
		fmt.Printf("%-10s %10s\n", ts_Option, ts)
		fmt.Printf("%-10s %10s\n", v_Option, v)
		fmt.Printf("%-10s %10s\n", vv_Option, vv)
		fmt.Printf("%-10s %10s\n", h_Option, h)
	}

	flag.Parse()

	if *HelpFlag {
		flag.Usage()
		os.Exit(0)
	}

	if *VeryVerboseFlag {
		*VerboseFlag = true
	}
	ScanPath = *PathFlag //need ScanPath for flags and later func
	if ScanPath == "" {
		fmt.Print("No path specified. Defaulting to current directory\n\n")
		ScanPath = "."
	}
	if !*VerboseFlag {
		fmt.Println("Scanning...")
	}

	//Goes through the directory looking for .pdf files
	filepath.Walk(ScanPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrPermission) {
				//do nothing
			} else {
				fmt.Printf("\nError accessing path %q: %v \n", path, err)
				os.Exit(0)
			}
		}
		if *VeryVerboseFlag {
			fmt.Println(path) //for very verbose
		}

		if !info.IsDir() && strings.HasSuffix(info.Name(), ".pdf") {
			if *VerboseFlag {
				fmt.Println("Found PDF:", path)
			}
			file, err := os.ReadFile(path)
			if err != nil {
				fmt.Println(err.Error())
			}
			str := string(file)

			//Looks for files with javascript indicators and appends them to a list
			TotalMatches, JavaMatch, JSMatch, AppMatch, AppHexMatch, OpenActionMatch,
				AAMatch, ThisMatch, ThisHexMatch := DetectingJavascript(str, *VerboseFlag)

			if TotalMatches == 0 {
				TotalClean += 1
			}
			if TotalMatches > 0 {
				SuspiciousFiles = append(SuspiciousFiles, path)
				TotalSuspect += 1
				MatchWarnings := []string{JavaWarning, JSWarning, AppWarning, AppHexWarning, OpenActionWarning,
					AAWarning, ThisWarning, ThisHexWarning}
				Matches := []bool{JavaMatch, JSMatch, AppMatch, AppHexMatch, OpenActionMatch, AAMatch,
					ThisMatch, ThisHexMatch}
				WarningIndex := 0
				for _, MatchValue := range Matches {
					if MatchValue {
						SuspiciousFiles = append(SuspiciousFiles, MatchWarnings[WarningIndex])
					}
					WarningIndex += 1
				}
				FileMatches[path] = int(TotalMatches)
			}
		}
		TotalFiles += 1
		return nil
	})

	//Shows the result of the scan and accepts the enter button to quit
	if len(SuspiciousFiles) == 0 {
		fmt.Println("\nResult: No suspicious files found")
		fmt.Print("\nClick Enter to quit")
		UserRead := bufio.NewReader(os.Stdin)
		input, err := UserRead.ReadString('\n')
		if err != nil {
			fmt.Println(err.Error())
		}
		if input == "\n" {
			fmt.Println("Quitting...")
			os.Exit(0)
		}
	}

	//Prints summary
	TotalPdfs = TotalSuspect + TotalClean
	fmt.Println("\n\n----- SUMMARY -----")
	fmt.Println("Files Scanned:", TotalFiles)
	fmt.Println("Pdfs Scanned:", TotalPdfs)
	fmt.Println("Suspicious Pdfs:", TotalSuspect)
	fmt.Println("Clean Pdfs:", TotalClean)
	TotalSeconds := time.Since(StartTime)  //Grabs time that has passed
	FloatSeconds := TotalSeconds.Seconds() //Converts the time passed to seconds, needed for the future calculations to work
	Minutes := int64(FloatSeconds) / 60
	IntSeconds := int64(FloatSeconds)
	SecondsRemaining := IntSeconds % 60
	fmt.Printf("Time: %dm %ds", Minutes, SecondsRemaining)
	fmt.Println()

	//Prints the suspicious pdf and what was found in it
	fmt.Println("\n----- Reasons -----")
	for _, value := range SuspiciousFiles {
		if strings.HasSuffix(value, ".pdf") {
			fmt.Println()
		}
		fmt.Println(value)
	}

	//Prints threat score for each file
	if *ThreatScoreFlag {
		fmt.Println("\n\n----- Threat Score -----")
		for File, Matches := range FileMatches {
			MatchesThreatScore(File, uint8(Matches))
			fmt.Println()
		}
	}

	fmt.Print("\nClick Enter to quit")
	UserRead := bufio.NewReader(os.Stdin)
	input, err := UserRead.ReadString('\n')
	if err != nil {
		fmt.Println(err.Error())
	}
	if input == "\n" {
		fmt.Println("Quitting...")
		os.Exit(0)
	}
}
