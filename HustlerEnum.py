import os
import subprocess
import time
import datetime
import requests
import json
import shutil
from bs4 import BeautifulSoup


def print_hustler_banner():
    banner = """
    #################################################
    #                                               #
    #            WELCOME TO HUSTLER TOOL            #
    #                                               #
    #################################################

    ██╗  ██╗██╗   ██╗███████╗████████╗██╗     ███████╗██████╗ 
    ██║  ██║██║   ██║██╔════╝╚══██╔══╝██║     ██╔════╝██╔══██╗
    ███████║██║   ██║███████╗   ██║   ██║     █████╗  ██████╔╝
    ██╔══██║██║   ██║╚════██║   ██║   ██║     ██╔══╝  ██╔══██╗
    ██║  ██║╚██████╔╝███████║   ██║   ███████╗███████╗██║  ██║
    ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝
    
    #################################################
    #         YOUR CYBERSECURITY SIDEKICK           #
    #       FAST & RELIABLE PENETRATION TESTING     #
    #################################################
    """
    print(banner)

def get_domain():
    domain = input("Please enter the domain to start testing: ")
    return domain



def log(message):
    """Log messages with timestamps."""
    print(f"{datetime.datetime.now()} - {message}")

def run_command(command, cwd=None):
    """Executes a shell command."""
    process = subprocess.Popen(command, shell=True, cwd=cwd)
    process.wait()

def file_exists(filepath):
    """Check if a file exists."""
    return os.path.isfile(filepath)



def urlscan(domain):
    log("#################################################")
    log("#             URLSCAN.IO SCAN FOR DOMAIN         #")
    log("#################################################")
    
    log(f"Date and Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    log("#################################################")
    
    if not domain:
        log("Usage: script.py urlscan example.com")
        return

    log(f"Domain: {domain}")
    os.makedirs(domain, exist_ok=True)
    os.chdir(domain)

    api_key = "eadbfb4b-ac3a-4b65-9c29-6f413c895b25"
    url = "https://urlscan.io/api/v1/search/"
    
    params = {
        "q": domain
    }
    headers = {
        "API-Key": api_key
    }
    
    # Send the request to the API
    log(f"Running URLScan for domain: {domain}...")
    response = requests.get(url, headers=headers, params=params)

    if response.status_code == 200:
        data = response.json()

        # Save the full result in a JSON file
        with open("urlscan_results.json", "w") as f:
            f.write(response.text)
        
        # Extract screenshot URL if available
        if data and "results" in data and data["results"]:
            screenshot_url = data["results"][0].get("screenshot")
            
            if screenshot_url:
                log(f"Downloading screenshot for {domain}...")
                screenshot_response = requests.get(screenshot_url)
                
                if screenshot_response.status_code == 200:
                    with open(f"{domain}_screenshot.png", "wb") as screenshot_file:
                        screenshot_file.write(screenshot_response.content)
                    log(f"Screenshot saved as {domain}_screenshot.png")
                else:
                    log("Error downloading screenshot.")
            else:
                log("No screenshot available for this scan.")
        else:
            log(f"No scan results found for {domain}.")
    else:
        log(f"Failed to retrieve data from URLScan API. Status code: {response.status_code}")
    
    os.chdir("..")
    
    
def passive_scraping(domain):
    log("#################################################")
    log("#       PASSIVE SCRAPING AND RESOLVING          #")
    log("#################################################")

    log(f"Date and Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    log("#################################################")

    if not domain:
        log("Usage: script.py passive_scraping example.com")
        return

    log(f"Domain: {domain}")
    os.makedirs(domain, exist_ok=True)
    os.chdir(domain)

    log("Running Amass...")
    run_command(f"../Tools/amass enum -passive -d {domain} 2>/dev/null | sort -u > 1.Amass.txt")

    log("Running SubFinder...")
    run_command(f"subfinder -silent -all -d {domain} | sort -u > 2.SubFinder.txt")

    log("Combining Results...")
    run_command("cat 1.Amass.txt 2.SubFinder.txt | tr 'A-Z' 'a-z' | sort -u > 3.Passive.SubDomains.txt")

    log("Running Resolving...")
    run_command(f"massdns -q -r ../Resources/resolvers.txt 3.Passive.SubDomains.txt | grep -E 'IN A [0-9]|CNAME' > 4.massDNS.Resolving.txt")

    run_command(f"grep '{domain}' 4.massDNS.Resolving.txt | cut -d ' ' -f1 | sed 's/.$//' | sort -u > 5.Live.SubDomains.txt")
    run_command("cat 3.Passive.SubDomains.txt 5.Live.SubDomains.txt | sort | uniq -u > 6.Died.SubDomains.txt")
    
    if file_exists("4.massDNS.Resolving.txt"):
        run_command(f"grep 'IN A' 4.massDNS.Resolving.txt | grep '{domain}' | cut -d ' ' -f5 | sort -u > 7.IP.Addresses.txt")

    os.chdir("..")



def wildcard_removal(domain):
    log("#################################################")
    log("#       WILDCARD SUBDOMAIN REMOVAL               #")
    log("#################################################")

    log(f"Date and Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    log("#################################################")

    if not domain:
        log("Usage: script.py wildcard_removal example.com")
        return

    log(f"Domain: {domain}")
    os.makedirs(domain, exist_ok=True)
    os.chdir(domain)

    log("Running Wildcard Removal...")
    run_command(f"grep -E 'CNAME|IN A' 4.massDNS.Resolving.txt | grep '{domain}' > 1.WildCardRemoval.txt")
    run_command(f"cat 1.WildCardRemoval.txt | cut -d ' ' -f1 | sort -u > 2.Removed.txt")

    log(f"Wildcard removal complete. Results saved in 2.Removed.txt")
    os.chdir("..")

def spidering(domain):
    log("#################################################")
    log("#       SPIDERING FOR URLs                       #")
    log("#################################################")

    log(f"Date and Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    log("#################################################")

    if not domain:
        log("Usage: script.py spidering example.com")
        return

    log(f"Domain: {domain}")
    os.makedirs(domain, exist_ok=True)
    os.chdir(domain)

    log("Running Spidering...")
    run_command(f"gospider -s https://{domain} -c 5 -o 1.Spidered.txt")

    log(f"Spidering complete. Results saved in 1.Spidered.txt")
    os.chdir("..")


def censys(domain):
    log("#################################################")
    log("#       CENSYS SCAN FOR DOMAIN                   #")
    log("#################################################")

    log(f"Date and Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    log("#################################################")

    if not domain:
        log("Usage: script.py censys example.com")
        return

    log(f"Domain: {domain}")
    os.makedirs(domain, exist_ok=True)
    os.chdir(domain)

    log("Running Censys Scan...")
    
    # Set the environment variables for the Censys API ID and Secret
    os.environ['CENSYS_API_ID'] = '6b36ae42-5085-40fc-a556-6b1f27010fc2'
    os.environ['CENSYS_API_SECRET'] = 'muxTKOfX4eY14vQAyRPWIMTemivslP44'

    run_command(f"censys search \"{domain}\" > 1.Censys.txt")

    log(f"Censys scan complete. Results saved in 1.Censys.txt")
    os.chdir("..")



# Main port scanning function
def port_scanning(domain):
    print("#################################################")
    print("#       PORT SCANNING FOR SUBDOMAINS             #")
    print("#################################################")

    print(f"Date and Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("#################################################")

    if not domain:
        print("Usage: script.py port_scanning example.com")
        return

    print(f"Domain: {domain}")
    os.makedirs(domain, exist_ok=True)  # Create a directory for the domain if it doesn't exist
    os.chdir(domain)  # Change to the domain directory

    # First Scan: Scan all ports (-p-)
    print("Running Full Port Scanning...")
    full_port_scan_command = f"nmap -p- -T4 -oN FullPortScan.txt {domain}"
    full_port_scan_output = run_command(full_port_scan_command)

    if full_port_scan_output:
        print("Full port scanning complete. Results saved in FullPortScan.txt")
    else:
        print("Full port scan failed.")
    print("Running Aggressive Scanning on common ports...")
    aggressive_scan_command = f"nmap -A -T4 -oN AggressiveScan.txt {domain}"
    aggressive_scan_output = run_command(aggressive_scan_command)
        
    if aggressive_scan_output:
        print(f"Aggressive scanning complete. Results saved in AggressiveScan.txt")
    else:
        print("Aggressive scan failed.")

    os.chdir("..")  # Return to the previous directory


def Dir_BruteForce(domain):
    log("#################################################")
    log("#       Directories & Files Brute Forcing       #")
    log("#################################################")
    log(f"Date and Time: {datetime.datetime.now()}")

    if not domain:
        log("Usage: script.py example.com")
        return

    log(f"Domain: {domain}")
    os.makedirs(domain, exist_ok=True)
    os.chdir(domain)

    log("Running FFUF...")
    
    # FFUF command to save results in JSON format for easier parsing
    ffuf_results_file = "ffuf_results.json"
    run_command(f"ffuf -u https://{domain}/FUZZ -w /home/kali/ReconHunter/newmedium.txt -o {ffuf_results_file} -of json")

    log("Directory & Files brute forcing complete. Results saved in ffuf_results.json")
    os.chdir("..")

    # Parsing the ffuf_results.json to extract only valid directories or files
    import json
    valid_results = []

    try:
        with open(f"{domain}/{ffuf_results_file}", 'r') as results_file:
            ffuf_data = json.load(results_file)
            
            # Extract valid results (e.g., status code 200 or other success criteria)
            for result in ffuf_data["results"]:
                if result["status"] == 200:  # Assuming status code 200 indicates success
                    valid_results.append(result["input"]["FUZZ"])  # Extracting the valid word (directory/file)
        
        # Save valid results to a new file
        with open(f"{domain}/valid_results.txt", 'w') as valid_file:
            for word in valid_results:
                valid_file.write(f"{word}\n")
        
        log(f"Valid results saved in valid_results.txt")
    except Exception as e:
        log(f"Error parsing ffuf results: {e}")

    # Optionally, search for specific pages like login or search page
    login_page = None
    search_page = None
    
    for word in valid_results:
        if "login" in word.lower():
            login_page = word
        if "search" in word.lower():
            search_page = word

    log(f"Login Page: {login_page}")
    log(f"Search Page: {search_page}")

# Example usage
# Dir_BruteForce('juice-shop.herokuapp.com')


if __name__ == "__main__":
    print_hustler_banner()
    domain = get_domain()
    print(f"Domain entered: {domain}")
    urlscan(domain)
    port_scanning(domain)
    passive_scraping(domain)
    wildcard_removal(domain)
    spidering(domain)
    censys(domain)
    Dir_BruteForce(domain)
 
 
    
    
    
