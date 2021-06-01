package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

type DebianReleaseData struct {
	ReleaseName  string `json:"releaseName" yaml:"releaseName" xml:"releaseName"`
	Status       string `json:"status" yaml:"status" xml:"status"`
	FixedVersion string `json:"fixed_version" yaml:"fixed_version" xml:"fixed_version"`
	Urgency      string `json:"urgency" yaml:"urgency" xml:"urgency"`
}

type DebianPackageCVEData struct {
	CVEID       string              `json:"cve_id" yaml:"cve_id" xml:"cve_id"`
	Description string              `json:"description" yaml:"description" xml:"description"`
	Scope       string              `json:"scope" yaml:"scope" xml:"scope"`
	Releases    []DebianReleaseData `json:"releases" yaml:"releases" xml:"releases"`
}

type DebianPackageData struct {
	Package string                 `json:"package" yaml:"package" xml:"package"`
	CVES    []DebianPackageCVEData `json:"cves" yaml:"cves" xml:"cves"`
}

type DebianVulnData struct {
	Packages []DebianPackageData `json:"packages" yaml:"packages" xml:"packages"`
}

func main() {
	fmt.Println("Warm up")

	// warm up round to get everything started
	unmarshalThenMarshalYAML()
	unmarshalThenMarshalJSON()
	unmarshalThenMarshalXML()

	fmt.Println("Start")
	amount := 5

	yamlTimes := []string{}
	jsonTimes := []string{}
	xmlTimes := []string{}

	for i := 0; i < amount; i++ {
		yamlTime := unmarshalThenMarshalYAML()
		yamlTimes = append(yamlTimes, fmt.Sprintf("%d", yamlTime))
		jsonTime := unmarshalThenMarshalJSON()
		jsonTimes = append(jsonTimes, fmt.Sprintf("%d", jsonTime))
		xmlTime := unmarshalThenMarshalXML()
		xmlTimes = append(xmlTimes, fmt.Sprintf("%d", xmlTime))
	}
	fmt.Println("YAML: ", strings.Join(yamlTimes, ", "))
	fmt.Println("JSON: ", strings.Join(jsonTimes, ", "))
	fmt.Println("XML: ", strings.Join(xmlTimes, ", "))

	fmt.Println("FIN")
}

func unmarshalThenMarshalYAML() int64 {
	dataBytes := ReadInBytes("./debian_vulns.yaml")

	start := time.Now()
	vulnData := DebianVulnData{}
	err := yaml.Unmarshal(dataBytes, &vulnData)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	yamlData, err := yaml.Marshal(&vulnData)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	duration := time.Since(start)
	log.Printf("Yaml time: %dms\n", duration.Milliseconds())

	if len(yamlData) < 10 {
		log.Println("yaml len ", len(yamlData))
	}

	return duration.Milliseconds()
}

func unmarshalThenMarshalJSON() int64 {

	dataBytes := ReadInBytes("./debian_vulns.json")

	start := time.Now()
	vulnData := DebianVulnData{}
	err := json.Unmarshal(dataBytes, &vulnData)

	jsonData, err := json.Marshal(vulnData)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	duration := time.Since(start)
	log.Printf("json time: %dms\n", duration.Milliseconds())

	if len(jsonData) < 10 {
		log.Println("yaml len ", len(jsonData))
	}
	return duration.Milliseconds()
}

func unmarshalThenMarshalXML() int64 {
	dataBytes := ReadInBytes("./debian_vulns.xml")

	start := time.Now()
	vulnData := DebianVulnData{}
	err := xml.Unmarshal(dataBytes, &vulnData)

	xmlData, err := xml.Marshal(vulnData)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	duration := time.Since(start)
	log.Printf("xml time: %dms\n", duration.Milliseconds())

	if len(xmlData) < 10 {
		log.Println("yaml len ", len(xmlData))
	}

	return duration.Milliseconds()
}

func ReadInBytes(fileName string) []byte {
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.Fatalln(err)
	}

	return data
}
