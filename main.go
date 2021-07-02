package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"sync"
	"time"
)

func main() {
	// get program name as argument
	arg1 := os.Args[1]
	program_name := arg1
	//get date
	date := time.Now().Format("01-02-2006")

	// make dirs for recon
	prepDirsCommand := "mkdir -p ./Programs/" + program_name + "/" + date
	exec.Command("bash", "-c", prepDirsCommand)
	// create go routine shiz
	var wg sync.WaitGroup

	//start commonspeak sub generation
	fmt.Println("\n\nGenerating Commonspeak2 possibilties on: " + program_name + ". . .")
	domains_list, err := os.Open("./Programs/" + program_name + "/recon-data/domains.txt")
	if err != nil {
		fmt.Println("Did you create an entry in ./Programs/ dir for " + program_name + "?")
	}
	defer domains_list.Close()
	scanner := bufio.NewScanner(domains_list)
	scanner.Split(bufio.ScanLines)
	var domains []string
	for scanner.Scan() {
		domains = append(domains, scanner.Text())
	}
	for i := 1; i < 8; i++ { //split jobs for blocks
		for _, domain := range domains {
			go runCommonspeakGeneration(domain, program_name, i, date, &wg)
			wg.Add(1)
		}
	}
	wg.Wait()
	fmt.Println("Starting Enumeration...")

	// run amass
	fmt.Println("\nStarting amass on: " + program_name + ". . .")
	programpath := "./Programs/" + program_name + "/" + date + "/"

	// run amass
	go RunAmass(program_name, programpath, &wg)
	wg.Add(1)

	// run subfinder
	fmt.Println("\nStarting Subfinder on: " + program_name + ". . .")
	programpath2 := "/home/sam/Programs/" + program_name + "/" + date + "/"

	//run subfinder
	go RunSubfinder(program_name, programpath2, &wg)
	wg.Add(1)
	wg.Wait()

	fmt.Println("subfinder, amass, commonspeak Complete!")

	//run shuffledns to acquire initial list of live hosts.
	fmt.Println("Starting massdns on amass/subfinder/commonspeak results . . . ")
	programpath3 := "/home/sam/Programs/" + program_name + "/" + date + "/"
	// combine enumeated subdomains into one file
	CombineSubsCmd := "ssh sam@143.198.146.77 'sort -u " + programpath3 + "subfinder.out " + programpath3 + "amass.out " + programpath3 + "commonspeakresults.out " + " > " + programpath3 + "subdomainscombined.txt'"
	CombineSubsOut, _ := exec.Command("bash", "-c", CombineSubsCmd).Output()
	fmt.Println(string(CombineSubsOut))
	// run shuffledns
	go RunMassdns(program_name, programpath, "1", &wg)
	wg.Add(1)
	wg.Wait()

	//run dnsgen (generate potential subdomains from already enumerated subdomains)
	programpath4 := "/home/sam/Programs/" + program_name + "/" + date + "/"
	go RunDNSGen(program_name, programpath4, &wg)
	wg.Add(1)

	fmt.Println("Waiting on dnsgen . . .")
	wg.Wait()

	//run shuffledns, mode 2. (resolves subdomains created by dnsgen)
	fmt.Println("Starting massdns on dnsgen results . . .")

	programpath5 := "/home/sam/Programs/" + program_name + "/" + date + "/"
	// run shuffledns
	go RunMassdns(program_name, programpath5, "2", &wg)
	wg.Add(1)

	fmt.Println("Waiting on shuffledns mode 2...")
	wg.Wait()
	fmt.Println("Complete!")
}

func RunSubfinder(fleetName string, outputPath string, wg *sync.WaitGroup) {
	subFinderCommand := "subfinder -dL " + outputPath + "domains.txt -o " + outputPath + "subfinder.out'"
	subFinderOut, _ := exec.Command("bash", "-c", subFinderCommand).Output()
	fmt.Println(string(subFinderOut))
	wg.Done()
}

func runCommonspeakGeneration(domain string, program string, blockNum int, date string, wg *sync.WaitGroup) {
	// run generation script
	NewNum := fmt.Sprintf("%02d", blockNum)
	runCommonspeakGenCommand := "/bin/bash ./shell-scripts/generate-commonspeak-list.sh " + domain + " " + program + " " + NewNum + " " + date + "'"
	fmt.Println(runCommonspeakGenCommand)
	runCommonspeakOut, _ := exec.Command("bash", "-c", runCommonspeakGenCommand).Output()
	fmt.Println(string(runCommonspeakOut))
	wg.Done()
}

func RunAmass(fleetName string, outputPath string, wg *sync.WaitGroup) {
	// run amass
	RunAmassCommand := "amass enum -timeout 30 -df " + outputPath + "domains.txt | tee -a " + outputPath + "amass.out'"
	RunAmassOut, err := exec.Command("bash", "-c", RunAmassCommand).Output()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(RunAmassOut))
	wg.Done()
}

func RunMassdns(fleetName string, outputPath string, mode string, wg *sync.WaitGroup) {
	if mode == "1" {
		// run shuffledns in mode 1: runs after initial enumeration.
		RunShufflednsCommand := "massdns -t A -o S --flush -w " + outputPath + "massdns0.out " + outputPath + "subdomainscombined.txt'"
		RunShufflednsOut, err := exec.Command("bash", "-c", RunShufflednsCommand).Output()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(RunShufflednsOut))
		editOutputCommand := "cat " + outputPath + "massdns0.out | awk '{print \\$1}' | sed 's/.$//' > " + outputPath + "massdns1.out"
		editOutputCommandOut, err := exec.Command("bash", "-c", editOutputCommand).Output()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(editOutputCommandOut))
		wg.Done()
	}
	if mode == "2" {
		// run shuffledns in mode 2: runs after dnsgen
		RunShufflednsCommand := "massdns -t A -o S --flush -w " + outputPath + "subdomains-results-massdns.txt " + outputPath + "dnsgen.out'"
		RunShufflednsOut, err := exec.Command("bash", "-c", RunShufflednsCommand).Output()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(RunShufflednsOut))
		editOutputCommand := "cat " + outputPath + "subdomains-results-massdns.txt | awk '{print \\$1}' | sed 's/.$//' > " + outputPath + "subdomains-results-final.txt"
		editOutputCommandOut, err := exec.Command("bash", "-c", editOutputCommand).Output()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(editOutputCommandOut))
		wg.Done()
	}
}

func RunDNSGen(fleetName string, outputPath string, wg *sync.WaitGroup) {
	runDNSGenCommand := "dnsgen " + outputPath + "massdns1.out | tee " + outputPath + "dnsgen.out'"
	runDNSGenOut, err := exec.Command("bash", "-c", runDNSGenCommand).Output()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(runDNSGenOut))
	wg.Done()
}
