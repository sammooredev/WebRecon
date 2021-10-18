# WebRecon - another wildcard domain recon script

## Dependencies
### Golang
tested on go1.16.3
### Other tools that must be reachable within your $PATH:
1. [amass](https://github.com/OWASP/Amass)
2. [subfinder](https://github.com/projectdiscovery/subfinder)
3. [shuffledns](https://github.com/projectdiscovery/shuffledns)
4. [dnsgen](https://github.com/ProjectAnte/dnsgen)

## What does this tool do?
1. takes input as a list of root-domains 
    * foo.com 
    * bar.com
    * . . .
2. runs amass, subfinder & prepends a lot of words to each root-domain
    * on prepending: currently doing this by splitting a wordlist isnt many chunks on disk, then starting a goroutine for each one. shit but it works.
3. combines the results of these 3 jobs into one file: subdomainscombined.txt
4. for each root-domain, it runs shuffledns with massdns' resolver list
    * wildcard filtering enabled. 
        * Wildcard filtering can only be used when specifying a root-domain to test with, this is why shuffledns is ran for each domain.
5. takes the output of shuffledns, and runs dnsgen. This generates a new file containing permutations of shuffledns' output.
6. runs shuffledns against the dnsgen output, to unconver even more subdomains.
7. outputs a directory for each domain, containing results. 

## How to use

Within the WebRecon folder, you can test the script with the "Google-Example" program.

1. Edit the domains within ./Program/Google-Example/domains.txt
2. Run WebRecon
      ./WebRecon Google-Example
      
3. Output is placed into ./Programs/Google-Example/<date-at-time-of-running>

## Resources: 

This tool is based off awesome blogs by [0xPatrik](https://twitter.com/0xpatrik?lang=en)
* [Subdomain Enumeration: 2019 Workflow](https://0xpatrik.com/subdomain-enumeration-2019/)
* [Subdomain Enumeration: Doing it a Bit Smarter](https://0xpatrik.com/subdomain-enumeration-smarter/)
