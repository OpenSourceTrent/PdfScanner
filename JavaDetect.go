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
	"slices"
	"strings"
	"sync"
	"time"
)

func SandBox() {
	// Future Endeavor, the goal is to be able to run the pdf in a sandbox for dynamic analysis.
	// This will likely take a lot of time to build, and even more to perfect.
	// But I hope to have a beta in the near future.
}

// Decodes any flate strings
func FlateDecoder(PdfStream []byte) ([]byte, error) {
	ByteData := bytes.NewReader(PdfStream)
	DecodedData, err := zlib.NewReader(ByteData)
	if err != nil {
		fmt.Println(err.Error())
		fmt.Println("Continuing...")
		return nil, err
	}
	defer DecodedData.Close()

	var DataOutput bytes.Buffer
	_, err = io.Copy(&DataOutput, DecodedData)
	if err != nil {
		fmt.Println(err.Error())
		fmt.Println("Continuing...")
		return nil, err
	}
	return DataOutput.Bytes(), err
}

// Searches for flate streams to pass to the decoder and returns the decoded stream
func FlateFinder(PdfBytes []byte) (DecodedData string) {
	var TotalFileData string
	var ReplaceFlateDecode string
	FlateLocation := regexp.MustCompile(`(?s)<<.*?/Filter\s*/FlateDecode.*?>>\s*stream\r?\n(.*?)\r?\nendstream`)
	LocationMatches := FlateLocation.FindAllSubmatch(PdfBytes, -1)
	if len(LocationMatches) == 0 { // Need so program doesn't fail if no flate string is found
		fmt.Println("No FlateDecode streams located")
		return
	} else {
		fmt.Printf("Found %d Flate streams\n", len(LocationMatches))
		for _, match := range LocationMatches {
			data := match[1]
			DecodedFlate, err := FlateDecoder(data) // Stores the passed decoded data
			if err != nil {
				fmt.Println(err.Error())
				fmt.Println("Continuing...")
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

// Function for ThreatScoring, currently experimental, doesn't determine whether the javascript is malicious or not.
// It scores based on how many indicators of javascript are found.
// I am working to make it have a more accurate scoring system
// func MatchesThreatScore(Path string, TotalMatches uint8) {
// 	if TotalMatches == 6 {
// 		fmt.Println(Path)
// 		fmt.Println("Severity: Critical")
// 	}
// 	if TotalMatches == 5 {
// 		fmt.Println(Path)
// 		fmt.Println("Severity: High")
// 	}
// 	if TotalMatches > 2 && TotalMatches < 5 {
// 		fmt.Println(Path)
// 		fmt.Println("Severity: Medium")
// 	}
// 	if TotalMatches < 2 {
// 		fmt.Println(Path)
// 		fmt.Println("Severity: Low")
// 	}
// }

// Func for saving everything to a logfile
func LogSave(SuspiciousFiles []string, TotalSuspect uint16, TotalClean uint16,
	TotalFiles uint32, StartTime time.Time, FileMatches map[string]int, ThreatScoreFlag bool,
	LogCapture io.Writer) {

	// Prints summary and allows user to exit
	TotalPdfs := TotalSuspect + TotalClean
	fmt.Fprintln(LogCapture, "\n\n----- SUMMARY -----")
	fmt.Fprintln(LogCapture, "Files Scanned:", TotalFiles)
	fmt.Fprintln(LogCapture, "Pdfs Scanned:", TotalPdfs)
	if len(SuspiciousFiles) == 0 {
		fmt.Fprintln(LogCapture, "No suspicious files found")
	} else {
		fmt.Fprintln(LogCapture, "Suspicious Pdfs:", TotalSuspect)
		fmt.Fprintln(LogCapture, "Clean Pdfs:", TotalClean)
	}
	TotalTime := time.Since(StartTime)  //Grabs time that has passed
	FloatSeconds := TotalTime.Seconds() //Converts the time passed to seconds, needed for the calculations to work
	Minutes := int64(FloatSeconds) / 60
	IntSeconds := int64(FloatSeconds)
	SecondsRemaining := IntSeconds % 60
	fmt.Fprintf(LogCapture, "Time: %dm %ds", Minutes, SecondsRemaining)
	fmt.Fprintln(LogCapture)

	// Prints the suspicious pdf and what was found in it
	fmt.Fprintln(LogCapture, "\n----- Reasons -----")
	for _, value := range SuspiciousFiles {
		if strings.HasSuffix(value, ".pdf") {
			fmt.Fprintln(LogCapture)
		}
		fmt.Fprintln(LogCapture, value)
	}

	// Prints threat score for each file
	// if ThreatScoreFlag {
	// 	fmt.Fprintln(LogCapture, "\n\n----- Threat Score -----")
	// 	for File, Matches := range FileMatches {
	// 		MatchesThreatScore(File, uint8(Matches))
	// 		fmt.Fprintln(LogCapture)
	// 	}
	// }

	// Reads for newline input to quit
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

func UrlMatcher(FileData string, wg *sync.WaitGroup) {
	defer wg.Done() //Needed for go routine sync

	var ParsedUrls []string
	var UrlRune []rune
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

	//List of all the matches for a clean "for loop", instead of a bunch of "if statements"
	RegExpMatchesList := []regexp.Regexp{*Http, *EduDomain, *GoogleUrl, *CalibreUrls,
		*AdobeUrls, *RedHatUrls, *UbuntuUrls, *MicrosoftUrls}

	//Goes through data and looks for matches
	for _, Data := range ParsedFileData { //  'continue' it ignores: for websites you aren't concerned about
		for _, RegexpMatch := range RegExpMatchesList {
			if RegexpMatch.MatchString(Data) {
				continue
			}
		}
		// Catches everything else that wasn't ignored
		// **This could prolly be condensed, working to get that done
		if Http.MatchString(Data) {
			HttpLocation := strings.Index(Data, "http")
			for _, Domain := range TopLevelDomainList {
				DomainLocation := strings.Index(Data, Domain)
				if DomainLocation != -1 {
					DomainLocation += len(Domain)
					for range DomainLocation {
						if HttpLocation < DomainLocation {
							UrlRune = append(UrlRune, rune(Data[HttpLocation]))
							HttpLocation += 1
						}
					}
					HttpMatch = string(UrlRune)
					ParsedUrls = append(ParsedUrls, HttpMatch)
					UrlRune = nil
				}
			}
		}

	}
	//sorts the list and removes duplicates Urls
	slices.Sort(ParsedUrls)
	ParsedUrls = slices.Compact(ParsedUrls)
	if len(ParsedUrls) != 0 {
		fmt.Println("Found Urls:")
		for _, Url := range ParsedUrls { // Prints all the leftover Urls
			fmt.Println(Url)
		}
	}

}

func RegexpMatcher(FileData string, Match string, MatchType int, wg *sync.WaitGroup) {
	defer wg.Done() //Needed for go routine sync
	var MatchRune []rune
	ParsedFileData := strings.Split(FileData, "\n")
	// Parses out lines so regexp can match the line easier.
	RegexpMatch := regexp.MustCompile(Match)
	for _, Data := range ParsedFileData { // Prints matches
		if RegexpMatch.MatchString(Data) {
			if MatchType == 1 { // For SuspiciousStrings{}
				MatchLocation := strings.Index(Data, Match)
				if MatchLocation != -1 {
					for range len(Data) - 1 {
						if Data[MatchLocation] == '<' {
							break
						}
						MatchRune = append(MatchRune, rune(Data[MatchLocation]))
						MatchLocation += 1
					}
					fmt.Println("Found:", string(MatchRune))
				}
				MatchRune = nil
			} else if MatchType == 2 { // For SuspiciousExecutions{}
				AreaSizeToDisplay := 10 // Sets how much to print around the match
				MatchLocation := strings.Index(Data, Match)
				if MatchLocation != -1 { // Calculates the area and prints that around the match
					start := max(0, MatchLocation-AreaSizeToDisplay)
					end := min(len(Data), MatchLocation+AreaSizeToDisplay)
					fmt.Println("Found:", Data[start:end])
				}

			}
		}

	}
}

// Function Looks for Javascript and sets true for each match it finds
func DetectingIOCs(FileData string, wg *sync.WaitGroup) {
	defer wg.Done()

	// If you only want to see data after the match, place match in SuspiciousStrings
	// If you want to see data in front of and after the match, place match in SuspiciousExecutions
	SuspiciousStrings := []string{"bUI: false", "/EmbeddedFile",
		"/EmbeddedFiles", "/JS", "/JavaScript", "/OpenAction"}
	SuspiciousExecutions := []string{".exe", ".elf", "cmd.exe"}

	// MatchType is for the RegexpMatcher to determine how to parse the matches
	MatchTypeStrings := 1
	MatchTypeExecs := 2

	for _, String := range SuspiciousStrings {
		wg.Add(1)
		go RegexpMatcher(FileData, String, MatchTypeStrings, wg)
	}
	for _, Execution := range SuspiciousExecutions {
		wg.Add(1)
		go RegexpMatcher(FileData, Execution, MatchTypeExecs, wg)
	}
}

func main() {
	var wg sync.WaitGroup   // Need for go routines
	StartTime := time.Now() //Grabs the time when the scan starts

	// Variables for Pdfs
	FileMatches := make(map[string]int) // Need for threatscore func
	var SuspiciousFiles []string        // List of files with javascript
	var TotalSuspect uint16 = 0         // Total suspect pdfs
	var TotalClean uint16 = 0           // Total clean pdfs
	var TotalPdfs uint16 = 0            // Total pdfs scanned
	var TotalFiles uint32 = 0           // Total files scanned
	var ScanPath string                 // The string needed for the path

	// Flags needed for command line options
	VeryVerboseFlag := flag.Bool("vv", false, "Very Verbose Mode (Prints all files, not just .pdf)")
	VerboseFlag := flag.Bool("v", false, "Verbose Mode")
	ThreatScoreFlag := flag.Bool("ts", false, "Shows threat score for each pdf")
	LogFlag := flag.Bool("l", false, "Logs stdout to a FileByteData")
	HelpFlag := flag.Bool("h", false, "Shows help page")

	// Custom help page
	flag.Usage = func() {

		// Flag Option strings
		UsageDisplay := "Usage:"         // Technically not an option, needed to display the Usage: "./JavaDetect [options] <path>" portion
		OptionDisplay := "---Options---" // Same principle, displays available options
		// ts_Option := "-ts"
		// v_Option := "-v"
		vv_Option := "-vv"
		l_Option := "-l"
		h_Option := "-h"

		// Flag Descriptions
		UsageInfo := "./JavaDetect [options] <path>"
		// ts := "Shows threat score for each pdf"
		// v := "Verbose Mode"
		vv := "Very Verbose Mode (Prints all files, not just .pdf)"
		l := "Logs stdout"
		h := "Shows help page"

		// This sets text alignment for the help page
		fmt.Printf("%-8s %8s\n", UsageDisplay, UsageInfo)
		fmt.Println()
		fmt.Println(OptionDisplay)
		fmt.Println()
		// fmt.Printf("%-8s %8s\n", ts_Option, ts)
		// fmt.Printf("%-8s %8s\n", v_Option, v)
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

	if !*VerboseFlag {
		fmt.Println("Scanning...")
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
			// if *VerboseFlag {
			// 	fmt.Println("Found PDF:", path)
			// }
			FileByteData, err := os.ReadFile(path)
			if err != nil {
				fmt.Println(err.Error())
			}

			// Huge pain that is needed to filter out all the data
			fmt.Println("\n", path)
			TotalFileData := FlateFinder(FileByteData)
			if TotalFileData == "" { //Need this first if condition in case there is no Flate to decode
				wg.Add(1)
				go UrlMatcher(string(FileByteData), &wg)
				wg.Add(1)
				go DetectingIOCs(string(FileByteData), &wg)
			} else {
				wg.Add(1)
				go UrlMatcher(TotalFileData, &wg)
				wg.Add(1)
				go DetectingIOCs(TotalFileData, &wg)
			}
			wg.Wait()
			// ParsedFileData := strings.Split(TotalFileData, "\n")
			// for _, Data := range ParsedFileData {
			// 	if len(Data) > 500 {
			// 		Index := 0
			// 		Count := 0
			// 		var ParsedDataString string
			// 		DataRune := []rune(Data)
			// 		for range len(Data) {
			// 			if Count == 200 {
			// 				ParsedFileData = append(ParsedFileData, ParsedDataString)
			// 				ParsedDataString = ""
			// 				Count = 0
			// 			}
			// 			ParsedDataString += string(DataRune[Index])
			// 			Index++
			// 			Count++
			// 		}
			// 		ParsedFileData = append(ParsedFileData, ParsedDataString)
			// 	}
			// }

			// Looks for files with javascript indicators and appends them to a list

			// DetectingIOCs(TotalPdfData)

			// if TotalMatches == 0 {
			// 	TotalClean += 1
			// }
			// if TotalMatches > 0 {
			// 	SuspiciousFiles = append(SuspiciousFiles, path)
			// 	TotalSuspect += 1
			// 	MatchWarnings := []string{JavaWarning, JSWarning, AppWarning, AppHexWarning, OpenActionWarning,
			// 		AAWarning, ThisWarning, ThisHexWarning}
			// 	Matches := []bool{JavaMatch, JSMatch, AppMatch, AppHexMatch, OpenActionMatch, AAMatch,
			// 		ThisMatch, ThisHexMatch}
			// 	WarningIndex := 0
			// 	for _, MatchValue := range Matches {
			// 		if MatchValue {
			// 			SuspiciousFiles = append(SuspiciousFiles, MatchWarnings[WarningIndex])
			// 		}
			// 		WarningIndex += 1
			// 	}
			// 	FileMatches[path] = int(TotalMatches)
			TotalPdfs += 1
		}
		// 	// }
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
		LogSave(SuspiciousFiles, TotalSuspect, TotalClean,
			TotalFiles, StartTime, FileMatches, *ThreatScoreFlag,
			LogCapture)

	}

	// Prints summary and allows user to exit
	fmt.Println("\n\n----- SUMMARY -----")
	fmt.Println("Files Scanned:", TotalFiles)
	fmt.Println("Pdfs Scanned:", TotalPdfs)
	// if len(SuspiciousFiles) == 0 {
	// 	fmt.Println("No suspicious files found")
	// } else {
	// 	fmt.Println("Suspicious Pdfs:", TotalSuspect)
	// 	fmt.Println("Clean Pdfs:", TotalClean)
	// }
	TotalTime := time.Since(StartTime)  // Grabs time that has passed
	FloatSeconds := TotalTime.Seconds() // Converts the time passed to seconds, needed for the calculations to work
	Minutes := int64(FloatSeconds) / 60
	IntSeconds := int64(FloatSeconds)
	SecondsRemaining := IntSeconds % 60
	fmt.Printf("Scan Time: %dm %ds", Minutes, SecondsRemaining)
	fmt.Println()

	// Prints the suspicious pdf and what was found in it
	// fmt.Println("\n----- Reasons -----")
	// for _, value := range SuspiciousFiles {
	// 	if strings.HasSuffix(value, ".pdf") {
	// 		fmt.Println()
	// 	}
	// 	fmt.Println(value)
	// }

	// Prints threat score for each file
	// if *ThreatScoreFlag {
	// 	fmt.Println("\n\n----- Threat Score -----")
	// 	for File, Matches := range FileMatches {
	// 		MatchesThreatScore(File, uint8(Matches))
	// 		fmt.Println()
	// 	}
	// }

	// Reads for newline input to quit
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
