package main

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"
)

// Struct needed for the summary portion
type PdfInfo struct {
	FoundUrls       []string
	FoundJavaScript []string
	FoundExecutions []string
}

// Map needed for the summary. Holds the different struct data for each Pdf
var FullPdfMap = make(map[string]*PdfInfo) //PdfInfo needs to be a pointer for consecutive map writes in the go func()s'

// Needed for the summary
var TotalNumOfUrls uint16
var TotalNumOfJavaScript uint16
var TotalNumOfExecutions uint16

func SandBox() {
	// Future Endeavor, the goal is to be able to run the pdf in a sandbox for dynamic analysis.
	// This will likely take a lot of time to build, and even more to perfect.
	// But I hope to have a beta in the near future.
}

// Decodes any flate strings
func FlateDecoder(PdfStream []byte, VerboseFlag bool) ([]byte, error) {
	ByteData := bytes.NewReader(PdfStream)
	DecodedData, err := zlib.NewReader(ByteData)
	if err != nil {
		if VerboseFlag {
			fmt.Println(err.Error())
			fmt.Println("Continuing...")

		}
		return nil, err
	}
	defer DecodedData.Close()

	var DataOutput bytes.Buffer
	_, err = io.Copy(&DataOutput, DecodedData)
	if err != nil {
		if VerboseFlag {
			fmt.Println(err.Error())
			fmt.Println("Continuing...")
		}
		return nil, err
	}
	return DataOutput.Bytes(), err
}

// Searches for flate streams to pass to the decoder and returns the decoded stream
func FlateFinder(PdfBytes []byte, VerboseFlag bool) (DecodedData string) {
	var TotalFileData string
	var ReplaceFlateDecode string
	FlateLocation := regexp.MustCompile(`(?s)<<.*?/Filter\s*/FlateDecode.*?>>\s*stream\r?\n(.*?)\r?\nendstream`)
	LocationMatches := FlateLocation.FindAllSubmatch(PdfBytes, -1)
	if len(LocationMatches) == 0 { // Need so program doesn't fail if no flate string is found
		if VerboseFlag {
			fmt.Println("No FlateDecode streams located")
		}
		return
	} else {
		if VerboseFlag {
			fmt.Printf("Located %d Flate streams\n", len(LocationMatches))
		}
		for _, match := range LocationMatches {
			data := match[1]
			DecodedFlate, err := FlateDecoder(data, VerboseFlag) // Stores the passed decoded data
			if err != nil {
				if VerboseFlag {
					fmt.Println(err.Error())
					fmt.Println("Continuing...")
				}
				continue
			}
			TotalFileData += string(DecodedFlate) // Stores all decoded data
		}
		// Removes all /FlateDecode matches since data is no longer needed
		ReplaceFlateDecode = FlateLocation.ReplaceAllString(string(PdfBytes), "")
		DecodedData = ReplaceFlateDecode + TotalFileData // Adds the decoded and replaced data together
		return DecodedData
	}

}

// Func for saving everything to a logfile
func LogSave(TotalFiles uint32, TotalPdfs uint16, TotalNumOfUrls uint16,
	TotalNumOfJavaScript uint16, TotalNumOfExecutions uint16, StartTime time.Time,
	LogCapture io.Writer) {

	TotalTime := time.Since(StartTime)  // Grabs time that has passed
	FloatSeconds := TotalTime.Seconds() // Converts the time passed to seconds, needed for the calculations to work
	Minutes := int64(FloatSeconds) / 60
	IntSeconds := int64(FloatSeconds)
	SecondsRemaining := IntSeconds % 60
	fmt.Printf("Scan Time: %dm %ds", Minutes, SecondsRemaining)

	fmt.Print("\n\n")
	fmt.Println("* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *")
	fmt.Println("*                              FOUND                            *")
	fmt.Println("* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *")
	fmt.Print("\n\n")

	var Index uint8 = 0
	for Name, Matches := range FullPdfMap {
		if Matches.FoundUrls == nil && Matches.FoundExecutions == nil &&
			Matches.FoundJavaScript == nil {
			continue
		} else {
			fmt.Println("------------------------------ PDF ------------------------------")
			fmt.Printf("%10s", Name)
			fmt.Println()
			fmt.Println()

			if Matches.FoundUrls != nil {
				fmt.Println("-------- Urls --------")
				for index, Match := range Matches.FoundUrls {
					fmt.Print(index+1, ": "+Match)
					fmt.Println()
				}
			}
			if Matches.FoundJavaScript != nil {
				fmt.Println("----- JavaScript -----")
				for index, Match := range Matches.FoundJavaScript {
					fmt.Print(index+1, ": "+Match)
					fmt.Println()
				}
			}
			if Matches.FoundExecutions != nil {
				fmt.Println("----- Executions -----")
				for index, Match := range Matches.FoundExecutions {
					fmt.Print(index+1, ": "+Match)
					fmt.Println()
				}
			}
			fmt.Println()
			Index++
		}
	}
	fmt.Println("\n----- SUMMARY -----")
	fmt.Println("Files Scanned:", TotalFiles)
	fmt.Println("Pdfs Scanned:", TotalPdfs)
	fmt.Println("Urls Found:", TotalNumOfUrls)
	fmt.Println("JavaScript Found:", TotalNumOfJavaScript)
	fmt.Println("Executions Found:", TotalNumOfExecutions)
	fmt.Print("\n\n")

}

func UrlMatcher(FileData string, wg *sync.WaitGroup, VerboseFlag bool, PdfName string) {
	defer wg.Done() //Needed for go routine sync
	var Continue bool
	var ParsedUrls []string
	var HttpMatch string
	TopLevelDomainList := []string{".org", ".bit", ".eth", ".crypto", ".onion", ".net", ".com", ".int", ".biz", ".bot", ".shop", ".top",
		".info", ".info", ".site", ".xyz", ".online", ".click", ".live", ".pl", ".br", ".life", ".ru", ".de", "store", ".id", ".club", ".fr", ".tk", ".cf", ".ga"}

	ParsedFileData := strings.Split(FileData, "\n") // Parses out new lines so regexp can match the line.

	// Regexp Matches for Urls
	Http := regexp.MustCompile("http.://")
	EduDomain := regexp.MustCompile("http.*.edu")
	GoogleUrl := regexp.MustCompile("http.*.google.com")
	CalibreUrls := regexp.MustCompile("http.*.calibre-ebook.com")
	AdobeUrls := regexp.MustCompile(".*.adobe.com")
	RedHatUrls := regexp.MustCompile(".*.redhat.com")
	UbuntuUrls := regexp.MustCompile(".*.ubuntu.com")
	MicrosoftUrls := regexp.MustCompile(".*.microsoft.com")
	LinuxKernelArchive := regexp.MustCompile(".*.kernel.org")
	Suse := regexp.MustCompile(".*.suse.com")
	VirtualBox := regexp.MustCompile(".*.virtualbox.org")

	//List of all the matches for a clean "for loop", instead of a bunch of "if statements"
	RegExpMatchesList := []regexp.Regexp{*EduDomain, *GoogleUrl, *CalibreUrls,
		*AdobeUrls, *RedHatUrls, *UbuntuUrls, *MicrosoftUrls, *LinuxKernelArchive,
		*Suse, *VirtualBox}

	//Goes through data and looks for matches
	for _, Data := range ParsedFileData { //  'continue' it ignores: for websites you aren't concerned about
		Continue = false
		for _, RegexpMatch := range RegExpMatchesList {
			if RegexpMatch.MatchString(Data) {
				Continue = true
			}
		}
		if Continue {
			continue
		}

		// Catches everything else that wasn't ignored
		if Http.MatchString(Data) {
			HttpLocation := strings.Index(Data, "http")
			for _, Domain := range TopLevelDomainList {
				DomainLocation := strings.Index(Data, Domain)
				if DomainLocation != -1 {
					Start := HttpLocation
					End := DomainLocation + 4
					HttpMatch = Data[Start:End]
					ParsedUrls = append(ParsedUrls, HttpMatch)
					TotalNumOfUrls++
				}
			}
		}

	}
	// Sorts the list and removes duplicate Urls
	slices.Sort(ParsedUrls)
	ParsedUrls = slices.Compact(ParsedUrls)
	if len(ParsedUrls) != 0 {
		FullPdfMap[PdfName] = &PdfInfo{FoundUrls: ParsedUrls}
	}

}

func RegexpMatcher(FileData string, Match string, MatchType int, wg *sync.WaitGroup, PdfName string) (JavaScriptMatches []string, ExecutionMatches []string) {

	var MatchRune []rune

	// Parses out lines so regexp can match the line easier.
	ParsedFileData := strings.Split(FileData, "\n")

	RegexpMatch := regexp.MustCompile(Match)
	for _, Data := range ParsedFileData { // Prints matches
		if RegexpMatch.MatchString(Data) {
			if MatchType == 1 { // For SuspiciousStrings{}
				MatchLocation := strings.Index(Data, Match)
				if MatchLocation != -1 {
					DataLength := len(Data) // To prevent any ridiculously large JS strings
					if len(Data) > 50 {
						DataLength = 49
					}
					for range DataLength {
						if Data[MatchLocation] == '<' {
							break
						}
						MatchRune = append(MatchRune, rune(Data[MatchLocation]))
						MatchLocation += 1
					}
					JavaScriptMatches = append(JavaScriptMatches, string(MatchRune))
					TotalNumOfJavaScript++ // Counter for summary
				}
				MatchRune = nil
			} else if MatchType == 2 { // For SuspiciousExecutions{}
				AreaSizeToDisplay := 10 // Sets how much to print in front of the match
				MatchLocation := strings.Index(Data, Match)
				if MatchLocation != -1 { // Calculates the area and prints that around the match
					Start := max(0, MatchLocation-AreaSizeToDisplay)
					End := min(len(Data), MatchLocation+4)
					ExecutionMatches = append(ExecutionMatches, Data[Start:End])
					TotalNumOfExecutions++ // Counter for summary
				}
			}
		}
	}
	return JavaScriptMatches, ExecutionMatches
}

// Function Looks for Javascript and sets true for each match it finds
func DetectingIOCs(FileData string, wg *sync.WaitGroup, VerboseFlag bool, PdfName string) {
	defer wg.Done()

	// Stores the data from the regexp scans and later passes that to the Pdf map
	var JavaScriptMatches []string
	var ExecutionMatches []string

	// If you only want to see data after the match, place match in SuspiciousStringsa
	// If you want to see data in front of and after the match, place match in SuspiciousExecutions
	SuspiciousStrings := []string{"bUI: false", "/EmbeddedFile",
		"/EmbeddedFiles", "/JS", "/JavaScript", "/OpenAction"}
	SuspiciousExecutions := []string{".exe", ".elf", ".deb", ".dll", ".sh", "powershell", "bash"}

	// MatchType is for the RegexpMatcher to determine how to parse the matches
	MatchTypeStrings := 1
	MatchTypeExecs := 2

	var innerwg sync.WaitGroup
	innerwg.Add(1)
	go func() {
		defer innerwg.Done()
		for _, String := range SuspiciousStrings {
			JavaScript, _ := RegexpMatcher(FileData, String, MatchTypeStrings, wg, PdfName)
			JavaScriptMatches = append(JavaScriptMatches, JavaScript...)
		}
	}()
	innerwg.Add(1)
	go func() {
		defer innerwg.Done()
		for _, Execution := range SuspiciousExecutions {
			_, Execs := RegexpMatcher(FileData, Execution, MatchTypeExecs, wg, PdfName)
			ExecutionMatches = append(ExecutionMatches, Execs...)
		}
	}()
	innerwg.Wait()

	slices.Sort(JavaScriptMatches)
	JavaScriptMatches = slices.Compact(JavaScriptMatches)
	slices.Sort(ExecutionMatches)
	ExecutionMatches = slices.Compact(ExecutionMatches)

	FullPdfMap[PdfName] = &PdfInfo{FoundJavaScript: JavaScriptMatches, FoundExecutions: ExecutionMatches}

}

// Counts the pdfs in a dir, needed for the scan progress feature
func PdfCounter(ScanPath string, PdfChan chan int) {
	var PdfAmount uint32 = 0
	filepath.Walk(ScanPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrPermission) {
				// Do nothing
			} else {
				fmt.Printf("\nScan monitoring err %q: %v \n", path, err)
			}
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".pdf") {
			PdfAmount += 1
		}
		return nil
	})
	PdfChan <- int(PdfAmount)
}

func ProgramSummaryWindows(StartTime time.Time, TotalFiles uint32, TotalPdfs uint16) {
	TotalTime := time.Since(StartTime)  // Grabs time that has passed
	FloatSeconds := TotalTime.Seconds() // Converts the time passed to seconds, needed for the calculations to work
	Minutes := int64(FloatSeconds) / 60
	IntSeconds := int64(FloatSeconds)
	SecondsRemaining := IntSeconds % 60

	fmt.Print("\n\n")
	fmt.Println("* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *")
	fmt.Println("*                              FOUND                            *")
	fmt.Println("* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *")
	fmt.Print("\n\n")

	var Index uint8 = 0
	for Name, Matches := range FullPdfMap {
		if Matches.FoundUrls == nil && Matches.FoundExecutions == nil &&
			Matches.FoundJavaScript == nil {
			continue
		} else {
			fmt.Println("------------------------------ PDF ------------------------------")
			fmt.Printf("%10s", Name)
			fmt.Println()
			fmt.Println()

			if Matches.FoundUrls != nil {
				fmt.Println("-------- Urls --------")
				for index, Match := range Matches.FoundUrls {
					fmt.Print(index+1, ": "+Match)
					fmt.Println()
				}
			}
			if Matches.FoundJavaScript != nil {
				fmt.Println("----- JavaScript -----")
				for index, Match := range Matches.FoundJavaScript {
					fmt.Print(index+1, ": "+Match)
					fmt.Println()
				}
			}
			if Matches.FoundExecutions != nil {
				fmt.Println("----- Executions -----")
				for index, Match := range Matches.FoundExecutions {
					fmt.Print(index+1, ": "+Match)
					fmt.Println()
				}
			}
			fmt.Println()
			Index++
		}
	}
	// Prints summary and exits
	fmt.Println("\n----- SUMMARY -----")
	fmt.Println("Files Scanned:", TotalFiles)
	fmt.Println("Pdfs Scanned:", TotalPdfs)
	fmt.Println("Urls Found:", TotalNumOfUrls)
	fmt.Println("JavaScript Found:", TotalNumOfJavaScript)
	fmt.Println("Executions Found:", TotalNumOfExecutions)
	fmt.Printf("Scan Time: %dm %ds", Minutes, SecondsRemaining)
	fmt.Print("\n\n")
	os.Exit(0)
}

func ProgramSummaryUnix(StartTime time.Time, TotalFiles uint32, TotalPdfs uint16) {
	TotalTime := time.Since(StartTime)  // Grabs time that has passed
	FloatSeconds := TotalTime.Seconds() // Converts the time passed to seconds, needed for the calculations to work
	Minutes := int64(FloatSeconds) / 60
	IntSeconds := int64(FloatSeconds)
	SecondsRemaining := IntSeconds % 60

	fmt.Print("\n\n")
	fmt.Println("\033[1;38;2;255;51;255m* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *")
	fmt.Println("*                              FOUND                            *")
	fmt.Println("* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *\033[0m")
	fmt.Print("\n\n")

	var Index uint8 = 0
	for Name, Matches := range FullPdfMap {
		if Matches.FoundUrls == nil && Matches.FoundExecutions == nil &&
			Matches.FoundJavaScript == nil {
			continue
		} else {
			fmt.Println("\033[38;2;255;0;0m------------------------------ PDF ------------------------------")
			fmt.Printf("%10s", Name)
			fmt.Println("\033[0m")
			fmt.Println()

			if Matches.FoundUrls != nil {
				fmt.Println("\033[38;2;0;204;0m-------- Urls --------")
				for index, Match := range Matches.FoundUrls {
					fmt.Print(index+1, ": "+Match)
					fmt.Println()
				}
				fmt.Print("\033[0m")
			}
			if Matches.FoundJavaScript != nil {
				fmt.Println("\033[38;2;255;173;17m----- JavaScript -----")
				for index, Match := range Matches.FoundJavaScript {
					fmt.Print(index+1, ": "+Match)
					fmt.Println()
				}
				fmt.Print("\033[0m")
			}
			if Matches.FoundExecutions != nil {
				fmt.Println("\033[38;2;0;204;204m----- Executions -----")
				for index, Match := range Matches.FoundExecutions {
					fmt.Print(index+1, ": "+Match)
					fmt.Println()
				}
				fmt.Print("\033[0m")
			}
			fmt.Println()
			Index++
		}
	}

	// Prints summary and exits
	fmt.Println("\n----- SUMMARY -----")
	fmt.Println("Files Scanned:", TotalFiles)
	fmt.Println("Pdfs Scanned:", TotalPdfs)
	fmt.Println("Urls Found:", TotalNumOfUrls)
	fmt.Println("JavaScript Found:", TotalNumOfJavaScript)
	fmt.Println("Executions Found:", TotalNumOfExecutions)
	fmt.Printf("Scan Time: %dm %ds", Minutes, SecondsRemaining)
	fmt.Print("\n\n")
	os.Exit(0)
}

func main() {
	var wg sync.WaitGroup   // Need for go routines
	StartTime := time.Now() //Grabs the time when the scan starts

	// Variables for Pdfs
	PdfChan := make(chan int) //  Pdf channel for the PdfCounter func
	var CurrentPdf uint8 = 0
	var ScanFinished uint8 = 0
	var TotalPdfs uint16 = 0  // Total pdfs scanned
	var TotalFiles uint32 = 0 // Total files scanned
	var ScanPath string       // The string needed for the path

	// Flags needed for command line options
	VeryVerboseFlag := flag.Bool("vv", false, "Very Verbose Mode (Prints all files, not just .pdf)")
	VerboseFlag := flag.Bool("v", false, "Verbose Mode")
	LogFlag := flag.Bool("l", false, "Logs stdout to a FileByteData")
	HelpFlag := flag.Bool("h", false, "Shows help page")

	// Custom help page
	flag.Usage = func() {

		// Flag Option strings
		UsageDisplay := "Usage:"         // Technically not an option, needed to display the Usage: "./JavaDetect [options] <path>" portion
		OptionDisplay := "---Options---" // Same principle, displays available options
		v_Option := "-v"
		vv_Option := "-vv"
		l_Option := "-l"
		h_Option := "-h"

		// Flag Descriptions
		UsageInfo := "./JavaDetect [options] <path>"
		v := "Verbose Mode"
		vv := "Very Verbose Mode (Prints all files, not just .pdf)"
		l := "Logs stdout"
		h := "Shows help page"

		// This sets text alignment for the help page
		fmt.Printf("%-8s %8s\n", UsageDisplay, UsageInfo)
		fmt.Println()
		fmt.Println(OptionDisplay)
		fmt.Println()
		fmt.Printf("%-8s %8s\n", v_Option, v)
		fmt.Printf("%-8s %8s\n", vv_Option, vv)
		fmt.Printf("%-8s %8s\n", l_Option, l)
		fmt.Printf("%-8s %8s\n", h_Option, h)
	}

	flag.Parse()

	//Looks for args and if nothing is provided then it shows help page
	PathArg := flag.Args()

	//Displays Help page
	if *HelpFlag {
		flag.Usage()
		os.Exit(0)
	}

	if *VeryVerboseFlag {
		*VerboseFlag = true
	}

	//Default behavior if no Args or path is given
	if len(PathArg) < 1 {
		// PathArg = append(PathArg, "/home/") //**Used for debugging**
		flag.Usage()
		os.Exit(0)
	}

	ScanPath = PathArg[0] // Need ScanPath for later func

	// Allows a progress report when hitting enter.
	// I don't think this is needed when running verbose mode
	if !*VerboseFlag {
		fmt.Println("Scanning...")
		go PdfCounter(ScanPath, PdfChan)
		PdfCounter := <-PdfChan
		go func() {
			for ScanFinished == 0 {
				Read := bufio.NewReader(os.Stdin)
				Enter, err := Read.ReadString('\n')
				if err != nil {
					fmt.Println(err.Error())
				}
				if Enter == "\n" && ScanFinished != 1 {
					fmt.Printf("Scanning:%d/%d Pdfs", CurrentPdf, PdfCounter)
				}
			}
		}()
	}

	// Goes through the directory looking for .pdf files
	filepath.Walk(ScanPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrPermission) {
				// Do nothing
				// If you don't handle this the scan will fail when it scans a protected folder.
			} else {
				fmt.Printf("\nError accessing path %q: %v \n", path, err)
				os.Exit(0)
			}
		}
		if *VeryVerboseFlag {
			fmt.Println(path)
		}

		//Ensures scanned item is not a folder and is of type .pdf
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".pdf") {
			if *VerboseFlag {
				fmt.Println("\nFound PDF:", path)
			}
			FileByteData, err := os.ReadFile(path)
			if err != nil {
				fmt.Println(err.Error())
			}
			PdfName := info.Name() // The Pdf's name, non-necessary variable assignment for better readability
			CurrentPdf += 1

			// Filters all the flate streams
			TotalFileData := FlateFinder(FileByteData, *VerboseFlag)
			// Runs scans against file data
			if TotalFileData == "" { //Need this first if condition in case there is no Flate to decode
				wg.Add(1)
				go UrlMatcher(string(FileByteData), &wg, *VerboseFlag, PdfName)
				wg.Add(1)
				go DetectingIOCs(string(FileByteData), &wg, *VerboseFlag, PdfName)
			} else {
				wg.Add(1)
				go UrlMatcher(TotalFileData, &wg, *VerboseFlag, PdfName)
				wg.Add(1)
				go DetectingIOCs(TotalFileData, &wg, *VerboseFlag, PdfName)

			}
			wg.Wait()

			TotalPdfs += 1
		}
		TotalFiles += 1
		return nil
	})

	// Need this in order to Log stdout
	if *LogFlag {
		// Gets the Date and Time - Needed to prevent the log file from being written over
		CurrentTime := time.Now()
		year, month, day := CurrentTime.Date()
		hour, min, sec := CurrentTime.Clock()

		FileName := fmt.Sprintf("LogFile_%d-%d-%d_%d:%d:%d.txt", month, day, year, hour, min, sec)
		LogFile, err := os.Create(FileName)
		if err != nil {
			fmt.Println(err.Error())
		}
		defer LogFile.Close()
		LogCapture := io.MultiWriter(os.Stdout, LogFile)
		LogSave(TotalFiles, TotalPdfs, TotalNumOfUrls,
			TotalNumOfJavaScript, TotalNumOfExecutions,
			StartTime, LogCapture)

	}
	// Prints summary and allows user to exit
	ScanFinished = 1 // For the scan progress

	if runtime.GOOS == "windows" {
		ProgramSummaryWindows(StartTime, TotalFiles, TotalPdfs)
	} else {
		ProgramSummaryUnix(StartTime, TotalFiles, TotalPdfs)
	}
}
