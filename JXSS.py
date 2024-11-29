import re
import requests
from bs4 import BeautifulSoup
import os
import time
from selenium import webdriver
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, UnexpectedAlertPresentException
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium_stealth import stealth
import random

def display_banner():
    banner = """
     ██╗██╗  ██╗███████╗███████╗
     ██║╚██╗██╔╝██╔════╝██╔════╝
     ██║ ╚███╔╝ ███████╗███████╗
██   ██║ ██╔██╗ ╚════██║╚════██║
╚█████╔╝██╔╝ ██╗███████║███████║
 ╚════╝ ╚═╝  ╚═╝╚══════╝╚══════╝
                                
    """
    print(banner)

# Load payloads from word list (file)
def load_payloads(filename):
    if os.path.exists(filename):
        with open(filename, 'r', errors='ignore') as file:
            return [line.strip() for line in file.readlines()]
    else:
        print(f"[-] Payload file {filename} not found.")
        return []



def fetch_js_files_and_inline_scripts(url):
    """Fetch the URLs of all JavaScript files and inline scripts from a webpage."""
    try:
        response = requests.get(url)
        if response.status_code != 200:
            print(f"[-] Error fetching URL {url}: Status code {response.status_code}")
            return [], []

        soup = BeautifulSoup(response.text, 'html.parser')
        script_tags = soup.find_all('script')

        js_files = []
        inline_scripts = []
        for script in script_tags:
            if script.get('src'):  # Check if the script tag has a src attribute (external JS)
                js_url = script.get('src')
                if js_url.startswith(('http://', 'https://')):
                    js_files.append(js_url)
                else:
                    js_files.append(os.path.join(url, js_url))  # Handle relative paths
            else:
                # Collect inline JavaScript content
                if script.string:
                    inline_scripts.append(script.string)
        return js_files, inline_scripts

    except Exception as e:
        print(f"[-] Error fetching JavaScript files and inline scripts from URL {url}: {e}")
        return [], []

def download_js_file(js_url):
    """Download JavaScript content from the given URL."""
    try:
        response = requests.get(js_url)
        if response.status_code == 200:
            return response.text
        else:
            print(f"[-] Error downloading JavaScript file {js_url}: Status code {response.status_code}")
            return None
    except Exception as e:
        print(f"[-] Error downloading JavaScript file {js_url}: {e}")
        return None

def detect_xss_vulnerabilities(content, payloads, js_url=None):
    """Detect potential XSS vulnerabilities in the given JavaScript content and attempt exploitation."""
    xss_patterns = [
        r"document\.write\(",
        r"innerHTML",
        r"eval\(",
        r"setTimeout\(",
        r"setInterval\(",
        r"src=.*?[\"\'].*?javascript:.*?[\"\']",
        r"<script.*?>",
        r"<iframe.*?>",
        r"<img.*?src=.*?[\"\'].*?javascript:.*?[\"\']",
    ]

    found_vulnerabilities = []
    successful_payloads = []  # To store the payloads that work
    
    for pattern in xss_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            vulnerability = f"[+] Potential XSS vulnerability found in {js_url or 'inline script'} using pattern: {pattern}"
            print(vulnerability)
            found_vulnerabilities.append(vulnerability)

            # Try payload injection
            for payload in payloads:
                if payload in content:
                    print(f"[!] Payload successfully injected: {payload}")
                    successful_payloads.append({
                        'url': js_url or 'inline script',
                        'pattern': pattern,
                        'payload': payload
                    })

    if not successful_payloads:
        print("[-] No payloads successfully injected.")
    else:
        print(f"\n[!] Summary of successful payload injections:")
        for entry in successful_payloads:
            print(f"    [+] URL/Script: {entry['url']} | Pattern: {entry['pattern']} | Payload: {entry['payload']}")
    
    return found_vulnerabilities, successful_payloads

def analyze_url_for_xss(url, payload_file):
    """Analyze all JavaScript files and inline scripts from a webpage URL for XSS vulnerabilities and attempt exploitation."""
    payloads = load_payloads(payload_file)
    if not payloads:
        print("[-] No payloads loaded.")
        return
    
    js_files, inline_scripts = fetch_js_files_and_inline_scripts(url)
    
    if not js_files and not inline_scripts:
        print(f"[-] No JavaScript files or inline scripts found on {url}.")
        return

    # Analyze external JS files
    for js_file_url in js_files:
        print(f"[*] Analyzing external JS file: {js_file_url}...")
        content = download_js_file(js_file_url)
        if content:
            detect_xss_vulnerabilities(content, payloads, js_file_url)

    # Analyze inline JS scripts
    for idx, inline_script in enumerate(inline_scripts):
        print(f"[*] Analyzing inline script {idx + 1}...")
        detect_xss_vulnerabilities(inline_script, payloads)


def start_driver():
    """Start a single instance of the Selenium WebDriver."""
    chrome_options = webdriver.ChromeOptions()
    chrome_options.add_argument('--ignore-certificate-errors')
    chrome_options.add_argument('--disable-dev-shm-usage')
    chrome_options.add_argument('--no-sandbox')

    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=chrome_options)
    driver.set_window_size(1024, 768)
    return driver

def xss_attack_using_params(driver, url, payload):
    """Perform an XSS attack using a single WebDriver session, ensuring alerts are handled."""
    print(f"[*] Starting XSS attack with payload: {payload}")
    target_url = f"{url}{payload}"

    try:
        # Handle any existing alerts before navigating to the next payload
        while True:
            try:
                WebDriverWait(driver, 2).until(EC.alert_is_present())
                alert = driver.switch_to.alert
                print(f"[!] Dismissing lingering alert with text: {alert.text}")
                alert.accept()  # Close lingering alert
            except TimeoutException:
                break  # No more alerts to handle

        # Navigate to the target URL with the current payload
        driver.get(target_url)

        # Wait for an alert to confirm XSS
        WebDriverWait(driver, 10).until(EC.alert_is_present())
        alert = driver.switch_to.alert
        alert_text = alert.text
        print(f"[+] XSS Alert triggered! Alert text: {alert_text}")
        alert.accept()  # Close the alert
    except UnexpectedAlertPresentException as e:
        print(f"[-] Unexpected alert encountered: {e.alert_text}")
        try:
            alert = driver.switch_to.alert
            alert.accept()  # Attempt to dismiss the unexpected alert
        except Exception:
            pass
    except Exception as e:
        print(f"[-] No alert found or other issue: {e}")



if __name__ == "__main__":
    url_to_scan = input("Enter the URL to scan for JavaScript XSS vulnerabilities: ")
    payload_file = input("Enter the path to your payload word list: ")
    analyze_url_for_xss(url_to_scan, payload_file)

    while True:
        ask = input("Do you want to perform aggressive Exploit on specific parameter? (y/n): ")
        if ask.lower() == "y":
            url_to_agg = input("Enter the URL with parameter to scan for XSS vulnerabilities: ")
            payloads = load_payloads(payload_file)

            driver = start_driver()  # Start the driver once
            try:
                for payload in payloads:
                    xss_attack_using_params(driver, url_to_agg, payload)
                    time.sleep(2)  # Optional delay for observation
            finally:
                driver.quit()  # Quit the driver after all payloads are tested
        elif ask.lower() == "n":
            exit()
        else:
            print("Invalid input. Please enter y or n.")
            continue