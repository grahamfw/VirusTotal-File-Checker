package main

import (
    "fmt"
    "flag"
    "os"
    "strings"
    "strconv"
    "time"
    "encoding/json"
    "gopkg.in/Iwark/spreadsheet.v2"
    "golang.org/x/net/context"
    "golang.org/x/oauth2/google"
    "github.com/williballenthin/govt"
)

var apikey string
var apiurl string
var rsrc string
var path string
var hashRow int
var firstBlankRow int


func init() {
	flag.StringVar(&apikey, "apikey", os.Getenv("VT_API_KEY"), "Set environment variable VT_API_KEY to your VT API Key or specify on prompt")
	flag.StringVar(&apiurl, "apiurl", "https://www.virustotal.com/vtapi/v2/", "URL of the VirusTotal API to be used.")
	flag.StringVar(&rsrc, "rsrc", "8ac31b7350a95b0b492434f9ae2f1cde", "resource of file to check VT for. Resource can be md5, sha-1 or sha-2 sum of a file.")
	flag.StringVar(&path, "path", "$HOME/", "File path where the file was found.")
}

// Function to check VirusTotal
func checkVT() (string, string, string, string, string, string, uint16, uint16, bool) {
	flag.Parse()
	c, err := govt.New(govt.SetApikey(apikey), govt.SetUrl(apiurl))
	checkError(err)
	notFound := false
	r, err := c.GetFileReport(rsrc)
	for resp, err := r, err; err != nil ; resp, err = r, err {
		_ = resp
		fmt.Println("Deferring by 60 seconds due to API limit reached...")
		time.Sleep(60000 * time.Millisecond)
		r, err = c.GetFileReport(rsrc)
		//_ = r
		//_ = err
	}

	if r.ResponseCode == 0 {
		fmt.Println(rsrc + " NOT KNOWN by VirusTotal")
		notFound = true
		return "none", "none", "none", "none", "none", "none", 0, 0, notFound
	} else {
		fmt.Printf("%s [%d/%d] IS KNOWN by VirusTotal\n", rsrc, r.Positives, r.Total)
		// Get values from VirusTotal 

		scans := r.Scans
		permalink := r.Permalink
		md5 := r.Md5
		kaspersky := scans["Kaspersky"].Result
		sophos := scans["Sophos"].Result
		eset := scans["ESET-NOD32"].Result
		scanDate := r.ScanDate
		positives := r.Positives
		total := r.Total

		return permalink, md5, kaspersky, sophos, eset, scanDate, positives, total, notFound
	}
}

// Main function
func main() {
	// Load spreadsheet data
	data := json.RawMessage(`<redacted>`)
	flag.Parse()
	//checkError(err)
	conf, err := google.JWTConfigFromJSON(data, spreadsheet.Scope)
	checkError(err)
	client := conf.Client(context.TODO())
	service := spreadsheet.NewServiceWithClient(client)
	spreadsheet, err := service.FetchSpreadsheet("<redacted>")
	checkError(err)
	sheet, err := spreadsheet.SheetByIndex(0)
	// To avoid declared and not used error
	_ = sheet
	checkError(err)

	//// Identify which column goes with which header

	// Check first column for hash value
	hashRow = 0
    m := sheet.Columns[0][hashRow].Value
	for (m != "") && (m != rsrc) {
		hashRow ++
		m = sheet.Columns[0][hashRow].Value
		//fmt.Println("m is ", m)
    }

    // Get column for SHA256 results
    sha256Col := 0
	sha256 := sheet.Rows[0][sha256Col].Value
	for (sha256 != "Results for SHA256") {
		sha256Col ++
		sha256 = sheet.Rows[0][sha256Col].Value
	}   

	// Get column for file path
    firstSeenPathCol := 0
	firstSeenPath := sheet.Rows[0][firstSeenPathCol].Value
	for (firstSeenPath != "First Seen Path") {
		firstSeenPathCol ++
		firstSeenPath = sheet.Rows[0][firstSeenPathCol].Value
	}    

	// Get column for md5 results
    md5Col := 0
	md5Hash := sheet.Rows[0][md5Col].Value
	for (md5Hash != "Results for MD5") {
		md5Col ++
		md5Hash = sheet.Rows[0][md5Col].Value
	}

	// Get column for Kaspersky Detection
	kasperskyCol := 0
	kaspersky := sheet.Rows[0][kasperskyCol].Value
	for (kaspersky != "Kaspersky Detection") {
		kasperskyCol ++
		kaspersky = sheet.Rows[0][kasperskyCol].Value
	}

	// Detected By column
	detectedByCol := 0
	detectedBy := sheet.Rows[0][detectedByCol].Value
	for (detectedBy != "Detected By") {
		detectedByCol ++
		detectedBy = sheet.Rows[0][detectedByCol].Value
	}

	// Get column for Sophos Detection
	sophosCol := 0
	sophos := sheet.Rows[0][sophosCol].Value
	for (sophos != "Sophos Detection") {
		sophosCol ++
		sophos = sheet.Rows[0][sophosCol].Value
	}

	// Get column for ESET Detection
	esetCol := 0
	eset := sheet.Rows[0][esetCol].Value
	for (eset != "ESET Detection") {
		esetCol ++
		eset = sheet.Rows[0][esetCol].Value
	}

	// Scanned on column - when VirusTotal scanned the file last
	scannedOnCol := 0
	scannedOn := sheet.Rows[0][scannedOnCol].Value
	for (scannedOn != "Scanned On") {
		scannedOnCol ++
		scannedOn = sheet.Rows[0][scannedOnCol].Value
	}

	// First seen computer column
	firstSeenCompCol := 0
	firsteenComp := sheet.Rows[0][firstSeenCompCol].Value
	for (firsteenComp != "First Seen Computer") {
		firstSeenCompCol ++
		firsteenComp = sheet.Rows[0][firstSeenCompCol].Value
	}

	// Last seen computer column
	lastSeenCompCol := 0
	lastSeenComp := sheet.Rows[0][lastSeenCompCol].Value
	for (lastSeenComp != "Last Seen Computer") {
		lastSeenCompCol ++
		lastSeenComp = sheet.Rows[0][lastSeenCompCol].Value
	}

	// First Seen Date column
	firstSeenDateCol := 0
	firstSeenDate := sheet.Rows[0][firstSeenDateCol].Value
	for (firstSeenDate != "First Seen Date") {
		firstSeenDateCol ++
		firstSeenDate = sheet.Rows[0][firstSeenDateCol].Value
	}

	// Last Seen Date column
	lastSeenDateCol := 0
	lastSeenDate := sheet.Rows[0][lastSeenDateCol].Value
	for (lastSeenDate != "Last Seen Date") {
		lastSeenDateCol ++
		lastSeenDate = sheet.Rows[0][lastSeenDateCol].Value
	}

    // Times Seen column
	timesSeenCol := 0
	timesSeen := sheet.Rows[0][timesSeenCol].Value
	for (timesSeen != "Times Seen") {
		timesSeenCol ++
		timesSeen = sheet.Rows[0][timesSeenCol].Value
	}	

	// Permalink column
	permalinkCol := 0
	permalinkVal := sheet.Rows[0][permalinkCol].Value
	for (permalinkVal != "Permalink") {
		permalinkCol ++
		permalinkVal = sheet.Rows[0][permalinkCol].Value
	}	

    // Get total number of rows by finding where the first blank one is
    firstBlankRow := 0
    k := sheet.Columns[0][firstBlankRow].Value
    for (k != "") {
    	firstBlankRow ++
    	k = sheet.Columns[0][firstBlankRow].Value
    }

	// Stale data check - only consider stale if under threshold (50%) and was not tagged as malicious 30+ days ago
	previouslySeenVal := sheet.Rows[hashRow][lastSeenDateCol].Value // When we last saw the file
	reScan := false
	if previouslySeenVal != "" {
		fmt.Println("Previously seen val is ", previouslySeenVal)
		detectedByVal := sheet.Rows[hashRow][detectedByCol].Value // Percent of AVs that flagged the files
		previousTimeStamp, _ := time.Parse("2006-01-02 15:04:05", previouslySeenVal)
		timeStamp := time.Now()
		diff := timeStamp.Sub(previousTimeStamp)
		days := int(diff.Hours() / 24)
		fmt.Println("Days old is", days)
		detectedByFloat, err := strconv.ParseFloat(detectedByVal, 64)
		_ = err
		if (days > 30) && float64(detectedByFloat) < 50.00 && ( hashRow != firstBlankRow ) {
			fmt.Println("Rescan of file should be done")
			reScan = true
			_ = reScan
		}
	}
	// Get row in question to check other values
	// hashRow, sha256Col, firstSeenPathCol, md5Col, kasperskyCol, detectedByCol, sophosCol, esetCol, scannedOnCol, firstSeenCompCol, lastSeenCompCol, firstSeenDateCol, lastSeenDateCol, timesSeenCol, permalinkCol, firstBlankRow, reScan := checkSpreadsheet()
	if ( hashRow == firstBlankRow || reScan == true ) {

		// Get info from VirusTotal
		permalink, md5, kaspersky, sophos, eset, scanDate, positives, total, notFound := checkVT()

		if reScan {
			fmt.Println("Stale data. Will update information from fresh query of VirusTotal...")
			// Update Detected By Value
			newDetectedByVal := float64(positives) / float64(total) * 100.00
			newDetectedByStr := strconv.FormatFloat(newDetectedByVal, 'f', 4, 32)
			sheet.Update(hashRow, detectedByCol, newDetectedByStr)
			fmt.Println("Detected percentage of total AVs:", newDetectedByStr)

			// Update Scanned On Value
			sheet.Update(hashRow, scannedOnCol, scanDate)

			// Update Last Seen Computer Value
			hostname, err := os.Hostname()
			checkError(err)
			computerName := strings.Split(hostname, ".")[0]
			sheet.Update(hashRow, lastSeenCompCol, computerName)

			// Update Last Seen Date Value
			timeStamp := time.Now().Format("2006-01-02 15:04:05")
			sheet.Update(hashRow, lastSeenDateCol, timeStamp)

			// Increment times seen
			timesSeenVal := (sheet.Rows[hashRow][timesSeenCol].Value)
			timesSeenInt, err := strconv.Atoi(timesSeenVal)
			_ = err
			timesSeenInt ++
			sheet.Update(hashRow, timesSeenCol, strconv.Itoa(timesSeenInt))

		} else if ( notFound == false ){
			// New entry in spreadsheet - new file not previously seen
			fmt.Println("Hash not found in spreadsheet. Will update with information from VirusTotal...")
			sheet.Update(firstBlankRow, sha256Col, rsrc) // SHA256 hash
			sheet.Update(firstBlankRow, firstSeenPathCol, path) // File path
			sheet.Update(firstBlankRow, md5Col, md5) // MD5 hash
			sheet.Update(firstBlankRow, kasperskyCol, kaspersky) // Kaspersky Detection name

			newDetectedByVal := float64(positives) / float64(total) * 100.00
			newDetectedByStr := strconv.FormatFloat(newDetectedByVal, 'f', 4, 32)
			sheet.Update(firstBlankRow, detectedByCol, newDetectedByStr) // Percentage of AVs that think this file is malicious
			fmt.Println("Detected percentage of total AVs:", newDetectedByStr)

			sheet.Update(firstBlankRow, sophosCol, sophos) // Sophos Detection name
			sheet.Update(firstBlankRow, esetCol, eset) // ESET Detection Name
			sheet.Update(firstBlankRow, scannedOnCol, scanDate) // Last time VirusTotal scanned the file

			hostname, err := os.Hostname()
			checkError(err)
			computerName := strings.Split(hostname, ".")[0]
			sheet.Update(firstBlankRow, firstSeenCompCol, computerName) // Name of computer for first seen computer
			sheet.Update(firstBlankRow, lastSeenCompCol, computerName) // Name of computer for last seen computer

			timeStamp := time.Now().Format("2006-01-02 15:04:05")
			sheet.Update(firstBlankRow, firstSeenDateCol, timeStamp) // Current timestamp for first seen date
			sheet.Update(firstBlankRow, lastSeenDateCol, timeStamp) // Current timestamp for last seen date
			sheet.Update(firstBlankRow, timesSeenCol, "1") // Counter for times we've seen the file - start at 1
			sheet.Update(firstBlankRow, permalinkCol, permalink) // Permalink for VirusTotal info

		} 
	} else {
		// Increment times seen
		fmt.Println("In spreadsheet with current data. Will increment times seen counter and update last seen computer and timestamps...")
		timesSeenVal := (sheet.Rows[hashRow][timesSeenCol].Value)
		timesSeenInt, err := strconv.Atoi(timesSeenVal)
		_ = err
		timesSeenInt ++
		sheet.Update(hashRow, timesSeenCol, strconv.Itoa(timesSeenInt))

		// Update Last Seen Computer Value
		hostname, err := os.Hostname()
		checkError(err)
		computerName := strings.Split(hostname, ".")[0]
		sheet.Update(hashRow, lastSeenCompCol, computerName)

		// Update Last Seen Date Value
		timeStamp := time.Now().Format("2006-01-02 15:04:05")
		sheet.Update(hashRow, lastSeenDateCol, timeStamp)

		// Output percentage data for bash script 
		fmt.Println("Detected percentage of total AVs:", (sheet.Rows[hashRow][detectedByCol].Value))
	}
	sheet.Synchronize()
}

func checkError(err error) {
    if err != nil {
        panic(err.Error())
    }
}