import sys
import io

# Fix Windows console encoding for Unicode output
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

import requests
from Header import Parser
import re
from adder import Adder
from colorama import Fore
import json
from Waf import Waf_Detect
from optparse import OptionParser
import subprocess
import sys
import os
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor


"""
This script parses command-line arguments for a vulnerability scanning application.

**Options:**

- `-f`, `--filename`: Specify a file containing URLs to scan (e.g., `urls.txt`).
- `-u`, `--url`: Scan a single URL (e.g., `http://example.com/?id=2`).
- `-o`, `--output`: Specify the filename to store scan results (e.g., `result.txt`).
- `-t`, `--threads`: Number of threads to use for concurrent requests (maximum 10).
- `-H`, `--headers`: Specify custom headers to send with requests.
- `--waf`: Enable web application firewall (WAF) detection and subsequent payload testing.
- `-w`, `--custom_waf`: Use specific payloads related to the detected WAF.
- `--crawl`: Enable crawling a website to find potential XSS vulnerabilities.
- `--pipe`: Pipe the output of another process as input to this script.

"""

parser = OptionParser()
parser.add_option("-f", "--filename", dest="filename", help="File containing URLs to scan")
parser.add_option("-u", "--url", dest="url", help="Single URL to scan (e.g. http://example.com/?id=2)")
parser.add_option("-o", "--output", dest="output", help="Output filename to store results")
parser.add_option("-t", "--threads", dest="threads", help="Number of threads (max 10)")
parser.add_option("-H", "--headers", dest="headers", help="Custom headers (comma-separated key:value pairs)")
parser.add_option("--waf", dest="waf", action="store_true", default=False,
                  help="Enable WAF detection")
parser.add_option("-w", "--custom_waf", dest="custom_waf", help="Specify WAF name for targeted payloads")
parser.add_option("--crawl", dest="crawl", action="store_true", default=False,
                  help="Enable crawling to discover URLs")
parser.add_option("--pipe", dest="pipe", action="store_true", default=False,
                  help="Read URLs from stdin (pipe)")

val, args = parser.parse_args()
filename = val.filename
threads = val.threads
output = val.output
url = val.url
crawl = val.crawl
waf = val.waf
pipe = val.pipe
custom_waf = val.custom_waf
headers = val.headers

try:
    if headers:
        print(Fore.WHITE + "[+] HEADERS: {}".format(headers))
        headers = Parser.headerParser(headers.split(','))
except AttributeError:
    headers = Parser.headerParser(headers.split())

try:
    threads = int(threads)
except TypeError:
    threads = 1
if threads > 10:
    threads = 7

if crawl:
    filename = f"{url.split('://')[1]}_katana"


class Main:

    def __init__(self, url=None, filename=None, output=None, headers=None):
        self.filename = filename
        self.url = url
        self.output = output
        self.headers = headers
        self.result = []
        self.dangerous_characters = Adder().dangerous_characters

    def read(self, filename):
        '''
        Read & sort GET urls from given filename
        '''
        print(Fore.WHITE + "READING URLS")
        try:
            # Cross-platform: read file and filter lines containing '='
            with open(filename, 'r') as f:
                lines = f.readlines()
            urls = sorted(set(line.strip() for line in lines if '=' in line))
            if not urls:
                print(Fore.GREEN + f"[+] NO URLS WITH GET PARAMETER FOUND")
            return urls
        except FileNotFoundError:
            print(Fore.RED + f"[-] File not found: {filename}")
            return []

    def write(self, output, value):
        '''
        Writes the output back to the given filename.
        '''
        if not output:
            return None
        with open(output, 'a') as f:
            f.write(str(value) + '\n')

    def replace(self, url, param_name, value):
        return re.sub(f"{re.escape(param_name)}=([^&]+)", f"{param_name}={value}", url)

    def bubble_sort(self, arr):
        """
        Sorts the given array of payloads in ascending order based on their
        'count' key (descending) so higher-count payloads come first.

        Args:
            arr (list): The list of payload dictionaries to be sorted.

        Returns:
            list: The sorted list of payloads.
        """
        n = len(arr)
        for i in range(n):
            for j in range(0, n - i - 1):
                count_j = arr[j].get("count", 0)
                count_j1 = arr[j + 1].get("count", 0)
                # Sort descending by count
                if count_j < count_j1:
                    arr[j], arr[j + 1] = arr[j + 1], arr[j]
        return arr

    def crawl(self):
        """
        Initiates a crawling process using Katana and saves the results.
        Katana discovers URLs with parameters that can be tested for XSS.

        Returns:
            None

        Raises:
            subprocess.CalledProcessError: If the Katana command fails.
        """
        try:
            print(Fore.WHITE + f"[+] Crawling {self.url} with Katana...")
            katana_cmd = f"katana -u {self.url} -d 3 -jc -kf -ef css,png,jpg,gif,svg,woff,ttf"

            output_data = subprocess.check_output(katana_cmd, shell=True, timeout=120)
            decoded = output_data.decode()

            # Save crawl results to file
            output_filename = self.filename if self.filename else f"{self.url.split('://')[1]}_katana"
            with open(output_filename, "w") as f:
                f.write(decoded)

            print(Fore.GREEN + f"[+] Crawl complete. Results saved to {output_filename}")

        except subprocess.CalledProcessError as e:
            print(Fore.RED + f"[-] Katana command failed: {e}")
        except subprocess.TimeoutExpired:
            print(Fore.RED + "[-] Katana crawl timed out after 120 seconds")
        except Exception as e:
            print(Fore.RED + f"[-] An error occurred during crawling: {e}")

    def parameters(self, url):
        """
        Extracts parameter names from the given URL's query string.

        Args:
            url (str): The URL to extract parameters from.

        Returns:
            list: A list of parameter names found in the URL.
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return list(params.keys())

    def parser(self, url, param_name, value):
        """
        Replaces a parameter's value in the URL and returns a dictionary
        of the modified URL components.

        Args:
            url (str): The URL to modify.
            param_name (str): The name of the parameter to replace.
            value (str): The new value to assign to the parameter.

        Returns:
            dict: A dictionary containing the parsed URL components,
                  including the modified query string and full URL.
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        # Replace the target parameter value
        if param_name in params:
            params[param_name] = [value]

        # Rebuild the query string
        new_query = urlencode(params, doseq=True)
        new_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))

        return {
            "scheme": parsed.scheme,
            "netloc": parsed.netloc,
            "path": parsed.path,
            "param_name": param_name,
            "value": value,
            "query": new_query,
            "full_url": new_url
        }

    def validator(self, arr, param_name, url):
        """
        Analyzes a list of potential parameter values (dangerous characters)
        for reflection vulnerabilities by injecting them and checking if they
        appear in the response.

        Args:
            arr (list): A list of dangerous characters to test.
            param_name (str): The name of the parameter to test.
            url (str): The base URL to test against.

        Returns:
            dict: A dictionary containing reflected characters, where the key
                  is the parameter name and the value is a list of characters
                  that were reflected.
        """
        reflected = []

        for char in arr:
            try:
                test_url = self.replace(url, param_name, f"arachnet{char}test")
                if self.headers:
                    response = requests.get(test_url, headers=self.headers, timeout=10)
                else:
                    response = requests.get(test_url, timeout=10)

                # Check if the injected character is reflected in the response
                if f"arachnet{char}test" in response.text:
                    reflected.append(char)
                    print(Fore.GREEN + f"    [+] Character '{char}' reflected in param '{param_name}'")
                else:
                    print(Fore.RED + f"    [x] Character '{char}' filtered in param '{param_name}'")

            except requests.exceptions.RequestException as e:
                print(Fore.RED + f"    [-] Request error testing '{char}': {e}")

        if reflected:
            return {param_name: reflected}
        return {}

    def fuzzer(self, url):
        """
        Performs fuzz testing on parameters extracted from a given URL by
        injecting dangerous characters and checking for reflection.

        Args:
            url (str): The URL to fuzz.

        Returns:
            list: A list of dictionaries containing parameter names and their
                  reflected dangerous characters.

        Raises:
            ValueError: If no parameters are identified in the URL.
        """
        params = self.parameters(url)
        if not params:
            print(Fore.RED + f"[-] No parameters found in URL: {url}")
            return []

        print(Fore.WHITE + f"[+] Found {len(params)} parameter(s): {', '.join(params)}")
        print(Fore.WHITE + "[+] Fuzzing for character reflection...")

        data = []
        for param in params:
            result = self.validator(self.dangerous_characters, param, url)
            if result:
                data.append(result)

        # Sort results using bubble_sort on internal data if needed
        if data:
            print(Fore.GREEN + f"[+] {len(data)} parameter(s) reflect dangerous characters")
        else:
            print(Fore.RED + "[-] No parameters reflect dangerous characters")

        return data


def filter_and_rank_payloads(arr, payload_file="payloads.json", firewall=None, threads=1):
    """
    Filters and ranks payloads based on firewall compatibility and occurrence
    within the target's reflected characters.

    Args:
        arr (list): List of reflected dangerous characters for a parameter.
        payload_file (str): Path to the JSON file containing payloads.
        firewall (str): The specific firewall to filter payloads for.
                        If None, generic (non-WAF-specific) payloads are used.
        threads (int): Number of threads (reserved for future use).

    Returns:
        list: A list of ranked payloads, with perfect matches first.
    """
    # Load payloads from JSON file
    script_dir = os.path.dirname(os.path.abspath(__file__))
    payload_path = os.path.join(script_dir, payload_file)

    try:
        with open(payload_path, 'r') as f:
            all_payloads = json.load(f)
    except FileNotFoundError:
        print(Fore.RED + f"[-] Payload file not found: {payload_path}")
        return []
    except json.JSONDecodeError:
        print(Fore.RED + f"[-] Invalid JSON in payload file: {payload_path}")
        return []

    # Filter payloads based on firewall (if specified)
    if firewall:
        firewall = firewall.lower()
        filtered = [p for p in all_payloads if p.get("waf") and firewall in p["waf"].lower()]
        if not filtered:
            print(Fore.YELLOW + f"[!] No payloads found for WAF '{firewall}', using generic payloads")
            filtered = [p for p in all_payloads if p.get("waf") is None]
    else:
        # Use generic payloads (no firewall specified)
        filtered = [p for p in all_payloads if p.get("waf") is None]

    if not filtered:
        print(Fore.RED + "[-] No matching payloads found")
        return []

    # Count payload attribute matches against reflected characters
    for payload in filtered:
        try:
            attributes = payload.get("Attribute", [])
        except (KeyError, TypeError):
            attributes = []

        try:
            count = 0
            for attr in attributes:
                if attr in arr:
                    count += 1
            payload["count"] = count
        except (KeyError, TypeError):
            payload["count"] = 0

    # Sort payloads by count (descending) and identify perfect matches
    def ranking_function(payload):
        """Rank payloads: higher count = better match, perfect matches first."""
        attributes = payload.get("Attribute", [])
        count = payload.get("count", 0)
        total_attrs = len(attributes) if attributes else 1
        # Perfect match bonus: all attributes are reflected
        is_perfect = 1 if (count == total_attrs and total_attrs > 0) else 0
        return (is_perfect, count)

    # Extract and rank identified payloads
    payload_list = []
    perfect_payloads = []

    for payload in filtered:
        attributes = payload.get("Attribute", [])
        count = payload.get("count", 0)

        if count == len(attributes) and len(attributes) > 0:
            # Prepend perfect payloads (all attributes reflected)
            perfect_payloads.append(payload)
        elif count > 0:
            # Include payloads with non-zero count
            payload_list.append(payload)

    # Sort each group by count descending
    perfect_payloads.sort(key=lambda p: p.get("count", 0), reverse=True)
    payload_list.sort(key=lambda p: p.get("count", 0), reverse=True)

    # Perfect payloads first, then partial matches
    return perfect_payloads + payload_list


class Scanner(Main):
    """Scanner extends Main with the actual XSS detection logic."""

    def scanner(self, url):
        """
        Main scanning method. Detects WAF, fuzzes parameters, selects payloads,
        and tests for reflected XSS.

        Args:
            url (str): The URL to scan for XSS vulnerabilities.

        Returns:
            str or None: The vulnerable URL if XSS is found, else None.
        """
        url = url.strip()
        if not url:
            return None

        # Print testing message
        print(Fore.WHITE + f"\n{'=' * 60}")
        print(Fore.WHITE + f"[+] TESTING: {url}")
        print(Fore.WHITE + f"{'=' * 60}")

        firewall = None

        # Check for WAF detection
        if waf:
            try:
                print(Fore.WHITE + "[+] Detecting WAF...")
                waf_detector = Waf_Detect(url)
                detected_waf = waf_detector.waf_detect()
                if detected_waf:
                    print(Fore.YELLOW + f"[!] WAF Detected: {detected_waf}")
                    firewall = detected_waf
                else:
                    print(Fore.GREEN + "[+] No WAF detected")
            except Exception as e:
                print(Fore.RED + f"[-] WAF detection error: {e}")

        # Use custom WAF if defined
        if custom_waf:
            firewall = custom_waf
            print(Fore.WHITE + f"[+] Using custom WAF profile: {firewall}")

        # Get potential vulnerabilities from fuzzer
        fuzz_results = self.fuzzer(url)

        if not fuzz_results:
            print(Fore.RED + f"[-] No reflectable parameters found for: {url}")
            return None

        # Iterate through each potential vulnerability
        for vuln in fuzz_results:
            for param_name, reflected_chars in vuln.items():
                print(Fore.WHITE + f"\n[+] Testing param '{param_name}' "
                                   f"with {len(reflected_chars)} reflected char(s): "
                                   f"{reflected_chars}")

                # Filter payloads based on WAF information
                ranked_payloads = filter_and_rank_payloads(
                    reflected_chars,
                    firewall=firewall
                )

                if not ranked_payloads:
                    print(Fore.RED + f"[-] No suitable payloads for param '{param_name}'")
                    continue

                print(Fore.WHITE + f"[+] Testing {len(ranked_payloads)} payloads...")

                # Try each filtered payload
                for payload_data in ranked_payloads:
                    payload = payload_data["Payload"].strip()

                    # Construct new URL with payload
                    parsed_data = self.parser(url, param_name, payload)
                    test_url = parsed_data["full_url"]

                    try:
                        # Send GET request with the payload
                        if self.headers:
                            response = requests.get(test_url, headers=self.headers, timeout=10)
                        else:
                            response = requests.get(test_url, timeout=10)

                        # Check for payload presence in the response
                        if payload in response.text:
                            print(Fore.GREEN + f"\n[★] XSS FOUND!")
                            print(Fore.GREEN + f"    URL: {test_url}")
                            print(Fore.GREEN + f"    Parameter: {param_name}")
                            print(Fore.GREEN + f"    Payload: {payload}")
                            self.result.append(test_url)

                            # Increment payload success count in the JSON file
                            payload_data["count"] = payload_data.get("count", 0) + 1
                            return test_url

                    except requests.exceptions.RequestException as e:
                        print(Fore.RED + f"    [-] Request failed: {e}")
                        continue

        print(Fore.RED + f"[-] No XSS vulnerability found for: {url}")
        return None


if __name__ == "__main__":
    urls = []
    ScannerInstance = Scanner(url=url, filename=filename, output=output, headers=headers)
    try:
        if url and not filename:
            ScannerInstance.scanner(url)
            if ScannerInstance.result:
                ScannerInstance.write(output, ScannerInstance.result[0])
            exit()
        elif filename and crawl:
            ScannerInstance.crawl()
            urls = ScannerInstance.read(filename)
        elif pipe:
            out = sys.stdin
            for line in out:
                urls.append(line.strip())
        else:
            urls = ScannerInstance.read(filename)
        print(Fore.GREEN + "CURRENT THREADS: {}".format(threads))
        with ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(ScannerInstance.scanner, urls)
        for i in ScannerInstance.result:
            ScannerInstance.write(output, i)
        print(Fore.WHITE + "COMPLETED")
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}")