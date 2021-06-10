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

type DebianReleaseDataNoTag struct {
	ReleaseName  string
	Status       string
	FixedVersion string
	Urgency      string
}

type DebianPackageCVEDataNoTag struct {
	CVEID       string
	Description string
	Scope       string
	Releases    []DebianReleaseDataNoTag
}

type DebianPackageDataNoTag struct {
	Package string
	CVES    []DebianPackageCVEDataNoTag
}

type DebianVulnDataNoTag struct {
	Packages []DebianPackageDataNoTag
}

type TimeData struct {
	Unmarshal int64
	Marshal   int64
}

type Times struct {
	Encoding string
	Times    []TimeData
}

func (t Times) String() string {
	unmarshal := make([]string, 0, len(t.Times))
	marshal := make([]string, 0, len(t.Times))
	totals := make([]string, 0, len(t.Times))
	for _, timeData := range t.Times {
		unmarshal = append(unmarshal, fmt.Sprintf("%d", timeData.Unmarshal))
		marshal = append(marshal, fmt.Sprintf("%d", timeData.Marshal))
		totals = append(totals, fmt.Sprintf("%d", (timeData.Marshal+timeData.Unmarshal)))
	}
	return fmt.Sprintf("[%s] Unmarshal: %s.\n[%s] Marshal: %s.\n[%s] Combined: %s.\n", t.Encoding, strings.Join(unmarshal, ", "), t.Encoding, strings.Join(marshal, ", "), t.Encoding, strings.Join(totals, ", "))
}

func main() {
	fmt.Println("Start")

	yamlDataBytes := readInBytes("./debian_vulns.yaml")
	jsonDataBytes := readInBytes("./debian_vulns.json")
	xmlDataBytes := readInBytes("./debian_vulns.xml")

	if true {
		fmt.Println("Warm up")
		// warm up round to get everything started
		unmarshalThenMarshalYAML(yamlDataBytes)
		unmarshalThenMarshalJSON(jsonDataBytes)
		unmarshalThenMarshalXML(xmlDataBytes)

		fmt.Println("Test begin")
		amount := 50

		yamlTimes := Times{Encoding: "YAML"}
		yamlNoTagTimes := Times{Encoding: "YAMLnoTag"}
		jsonTimes := Times{Encoding: "JSON"}
		jsonNoTagTimes := Times{Encoding: "JSONnoTag"}
		xmlTimes := Times{Encoding: "XML"}
		xmlNoTagTimes := Times{Encoding: "XMLnoTag"}

		for i := 0; i < amount; i++ {
			yamlTimeUnmarshal, yamlTimeMarshal := unmarshalThenMarshalYAML(yamlDataBytes)
			yamlTimes.Times = append(yamlTimes.Times, TimeData{Unmarshal: yamlTimeUnmarshal, Marshal: yamlTimeMarshal})
			yamNoTagTimeUnmarshal, yamlTimeNoTagMarshal := unmarshalThenMarshalYAMLNoTags(yamlDataBytes)
			yamlNoTagTimes.Times = append(yamlNoTagTimes.Times, TimeData{Unmarshal: yamNoTagTimeUnmarshal, Marshal: yamlTimeNoTagMarshal})

			jsonTimeUnmarshal, jsonTimeMarshal := unmarshalThenMarshalJSON(jsonDataBytes)
			jsonTimes.Times = append(jsonTimes.Times, TimeData{Unmarshal: jsonTimeUnmarshal, Marshal: jsonTimeMarshal})
			jsonNoTagTimeUnmarshal, jsonNoTagTimeMarshal := unmarshalThenMarshalJSONNoTag(jsonDataBytes)
			jsonNoTagTimes.Times = append(jsonNoTagTimes.Times, TimeData{Unmarshal: jsonNoTagTimeUnmarshal, Marshal: jsonNoTagTimeMarshal})

			xmlTimeUnmarshal, xmlTimeMarshal := unmarshalThenMarshalXML(xmlDataBytes)
			xmlTimes.Times = append(xmlTimes.Times, TimeData{Unmarshal: xmlTimeUnmarshal, Marshal: xmlTimeMarshal})
			xmlNoTagTimeUnmarshal, xmlNoTagTimeMarshal := unmarshalThenMarshalXMLNoTag(xmlDataBytes)
			xmlNoTagTimes.Times = append(xmlNoTagTimes.Times, TimeData{Unmarshal: xmlNoTagTimeUnmarshal, Marshal: xmlNoTagTimeMarshal})
			fmt.Printf("completed loop %d \n", i)
		}
		fmt.Println("Times:")
		fmt.Println(yamlTimes.String())
		fmt.Println(jsonTimes.String())
		fmt.Println(xmlTimes.String())
		fmt.Println("")
		fmt.Println(yamlNoTagTimes.String())
		fmt.Println(jsonNoTagTimes.String())
		fmt.Println(xmlNoTagTimes.String())
	}

	fmt.Println("FIN")
}

func unmarshalThenMarshalYAML(dataBytes []byte) (int64, int64) {

	vulnData := DebianVulnData{}

	startUnmarshal := time.Now()
	err := yaml.Unmarshal(dataBytes, &vulnData)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	unmarshalDuration := time.Since(startUnmarshal)

	startMarshal := time.Now()
	yamlData, err := yaml.Marshal(&vulnData)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	marshalDuration := time.Since(startMarshal)

	log.Printf("YAML time unmarshal: %dms. marshal: %d\n", unmarshalDuration.Milliseconds(), marshalDuration.Milliseconds())
	log.Panicln("YAML packages len ", len(vulnData.Packages))
	log.Println("YAML output len ", len(yamlData))

	return unmarshalDuration.Milliseconds(), marshalDuration.Milliseconds()
}

func unmarshalThenMarshalYAMLNoTags(dataBytes []byte) (int64, int64) {

	vulnData := DebianVulnDataNoTag{}

	startUnmarshal := time.Now()
	err := yaml.Unmarshal(dataBytes, &vulnData)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	unmarshalDuration := time.Since(startUnmarshal)

	startMarshal := time.Now()
	yamlData, err := yaml.Marshal(&vulnData)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	marshalDuration := time.Since(startMarshal)

	log.Printf("YAML no tag time unmarshal: %dms. marshal: %d\n", unmarshalDuration.Milliseconds(), marshalDuration.Milliseconds())
	log.Panicln("YAML no tag packages len ", len(vulnData.Packages))
	log.Println("YAML no tag output len ", len(yamlData))

	return unmarshalDuration.Milliseconds(), marshalDuration.Milliseconds()
}

func unmarshalThenMarshalJSON(dataBytes []byte) (int64, int64) {

	vulnData := DebianVulnData{}

	startUnmarshal := time.Now()
	err := json.Unmarshal(dataBytes, &vulnData)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	unmarshalDuration := time.Since(startUnmarshal)

	startMarshal := time.Now()
	jsonData, err := json.Marshal(vulnData)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	marshalDuration := time.Since(startMarshal)

	log.Printf("JSON time unmarshal: %dms. marshal: %d\n", unmarshalDuration.Milliseconds(), marshalDuration.Milliseconds())
	log.Panicln("JSON packages len ", len(vulnData.Packages))
	log.Println("JSON output len ", len(jsonData))

	return unmarshalDuration.Milliseconds(), marshalDuration.Milliseconds()
}

func unmarshalThenMarshalJSONNoTag(dataBytes []byte) (int64, int64) {

	vulnData := DebianVulnDataNoTag{}

	startUnmarshal := time.Now()
	err := json.Unmarshal(dataBytes, &vulnData)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	unmarshalDuration := time.Since(startUnmarshal)

	startMarshal := time.Now()
	jsonData, err := json.Marshal(vulnData)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	marshalDuration := time.Since(startMarshal)

	log.Printf("JSON no tag time unmarshal: %dms. marshal: %d\n", unmarshalDuration.Milliseconds(), marshalDuration.Milliseconds())
	log.Panicln("JSON no tag packages len ", len(vulnData.Packages))
	log.Println("JSON no tag output len ", len(jsonData))

	return unmarshalDuration.Milliseconds(), marshalDuration.Milliseconds()
}

func unmarshalThenMarshalXML(dataBytes []byte) (int64, int64) {

	vulnData := DebianVulnData{}
	startUnmarshal := time.Now()
	err := xml.Unmarshal(dataBytes, &vulnData)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	unmarshalDuration := time.Since(startUnmarshal)

	startMarshal := time.Now()
	xmlData, err := xml.Marshal(vulnData)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	marshalDuration := time.Since(startMarshal)

	log.Printf("XML time unmarshal: %dms. marshal: %d\n", unmarshalDuration.Milliseconds(), marshalDuration.Milliseconds())
	log.Panicln("XML packages len ", len(vulnData.Packages))
	log.Println("XML output len ", len(xmlData))

	return unmarshalDuration.Milliseconds(), marshalDuration.Milliseconds()
}

func unmarshalThenMarshalXMLNoTag(dataBytes []byte) (int64, int64) {

	vulnData := DebianVulnDataNoTag{}
	startUnmarshal := time.Now()
	err := xml.Unmarshal(dataBytes, &vulnData)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	unmarshalDuration := time.Since(startUnmarshal)

	startMarshal := time.Now()
	xmlData, err := xml.Marshal(vulnData)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	marshalDuration := time.Since(startMarshal)

	log.Printf("XML no tag time unmarshal: %dms. marshal: %d\n", unmarshalDuration.Milliseconds(), marshalDuration.Milliseconds())
	log.Panicln("XML no tag packages len ", len(vulnData.Packages))
	log.Println("XML no tag output len ", len(xmlData))

	return unmarshalDuration.Milliseconds(), marshalDuration.Milliseconds()
}

func readInBytes(fileName string) []byte {
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.Fatalln(err)
	}

	return data
}
