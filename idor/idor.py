import os, sys, time, socket, argparse, requests
import io

# Fix Windows console encoding for Unicode output
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

from urllib.parse import urljoin
<<<<<<< HEAD
from bs4 import BeautifulSoup
=======
import subprocess 
from optparse import OptionParser
>>>>>>> b708ea6687ccf277ffdcc35d1b3829e01d8a571d
from colorama import Fore, Back, Style

parser = OptionParser() 

parser.add_option("-u", dest="url", help="scan a single URL. Eg: http://example.com/?id=2")
parser.add_option('-f', dest='filename', help="specify Filename to scan. Eg: urls.txt etc")
parser.add_option('-o', dest='output', help="filename to store output. Eg: result.txt")

val,args = parser.parse_args()
url=val.url
filename=val.filename
output=val.output

red = Fore.RED + Style.BRIGHT
green = Fore.GREEN + Style.BRIGHT
yellow = Fore.YELLOW + Style.BRIGHT
blue = Fore.BLUE + Style.BRIGHT
purple = Fore.MAGENTA + Style.BRIGHT
cyan = Fore.CYAN + Style.BRIGHT
white = Fore.WHITE + Style.BRIGHT
no_colour = Fore.RESET + Back.RESET + Style.RESET_ALL

ask = green + "[" + white + "?" + green + "] " + blue
success = yellow + "[" + white + "√" + yellow + "] " + green
error = blue + "[" + white + "!" + blue + "] " + red
info = yellow + "[" + white + "+" + yellow + "] " + cyan
info2 = green + "[" + white + "•" + green + "] " + purple


class IDORScanner:
    """
    IDOR (Insecure Direct Object Reference) vulnerability scanner.

    Crawls a target URL, discovers endpoints, and tests them with various
    parameter values, payloads, and HTTP methods to detect potential IDOR
    vulnerabilities.
    """

    def __init__(self, target_url=None, output_file=None):
        self.target_url = target_url
        self.output_file = output_file
        self.base_url = None
        self.visited_urls = set()
        self.results = []

        self.endpoints = [
            "/myaccount/uid=12",
            "User/Login",
            "/photos/002548",
            "/item/193422",
            "/app/accountInfo?acct=admin",
            "/transaction.php?id=74656",
            "/change_password.php?userid=1701",
            "/display_file.php?file.txt",
            "/balance?acc=123",
            "/changepassword?user=someuser",
            "/showImage?img=img00011",
            "/accessPage?menuitem=12",
            "/accountInfo/accId=2",
            "/testpage?invoiceId=12345",
            "/app/accountInfo?act=requestor"
        ]

        self.parameters = [
            "use", "id", "userid", "username", "user", "blog", "post",
            "info", "profile", "obj", "object", "query", "create", "delete",
            "edit", "retrieve", "get", "put", "patch", "del", ":id"
        ]

        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36",
            "Accept": "application/json"
        }

        self.test_values = ["1", "2", "3", "4"]
        self.payloads = ["../", "/etc/passwd", "admin"]
        self.http_methods = ["GET", "POST", "PUT", "DELETE"]

        self.sensitive_endpoints = [
            "/api/grades",
            "/api/student_info",
            "/api/attendance",
            "/api/exam_results"
        ]

<<<<<<< HEAD
    def crawl(self, url, base_url, depth=1):
        """
        Recursively crawl from a given URL, collecting discovered links.
=======
def read(filename):
     urls = []
     try:
         result = subprocess.run(['cat', filename], capture_output=True)
         urls = result.stdout
     except subprocess.CalledProcessError as e:
         print(f"Error: {e}")
     return urls

def crawl(url, base_url):
    visited_urls.add(url)
    response = requests.get(url, headers=headers)
    soup = BeautifulSoup(response.content, "html.parser")
>>>>>>> b708ea6687ccf277ffdcc35d1b3829e01d8a571d

        Args:
            url (str): The URL to crawl.
            base_url (str): The base URL to restrict crawling scope.
            depth (int): How many levels deep to crawl.
        """
        if depth <= 0 or url in self.visited_urls:
            return

        self.visited_urls.add(url)
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            soup = BeautifulSoup(response.content, "html.parser")

            for link in soup.find_all("a"):
                href = link.get("href")
                if href:
                    # Resolve relative URLs
                    full_url = urljoin(url, href)
                    if full_url.startswith(base_url) and full_url not in self.visited_urls:
                        self.crawl(full_url, base_url, depth - 1)
        except requests.exceptions.RequestException as e:
            print(error + f"Crawl error for {url}: {e}")

    def test_request(self, url, method):
        """
        Send an HTTP request with the given method to the URL.

        Args:
            url (str): The target URL.
            method (str): HTTP method (GET, POST, PUT, DELETE).

        Returns:
            tuple: (status_code, response_text) or (None, error_message).
        """
        try:
            response = requests.request(method, url, headers=self.headers, timeout=10)
            return response.status_code, response.text
        except requests.exceptions.ConnectionError as e:
            return None, f"Connection Error: {url} - {str(e)}"
        except requests.exceptions.RequestException as e:
            return None, f"Request Error: {url} - {str(e)}"

    def analyze_response(self, url, method, status_code, response_text):
        """
        Analyze the HTTP response for potential IDOR vulnerabilities.

        Args:
            url (str): The tested URL.
            method (str): The HTTP method used.
            status_code (int): Response status code.
            response_text (str): Response body text.
        """
        if status_code is None:
            print(error + f"Could not connect: {url} | Method: {method}")
            return

        if status_code == 200:
            print(success + f"Potential IDOR vulnerability found for URL: {url} | "
                            f"Method: {method} | Status Code: {status_code}")
            self.results.append({
                "url": url,
                "method": method,
                "status_code": status_code,
                "type": "potential_idor"
            })

            # Check sensitive endpoints
            for sensitive_endpoint in self.sensitive_endpoints:
                sensitive_url = urljoin(self.base_url, sensitive_endpoint)
                sensitive_status_code, sensitive_response_text = self.test_request(sensitive_url, "GET")

                if sensitive_status_code == 200:
                    print(success + f"Sensitive data accessed at endpoint: "
                                    f"{sensitive_endpoint} | URL: {sensitive_url}")
                    self.results.append({
                        "url": sensitive_url,
                        "method": "GET",
                        "status_code": sensitive_status_code,
                        "type": "sensitive_data_access"
                    })
                else:
                    print(error + f"No sensitive data accessed at endpoint: {sensitive_endpoint}")
        elif status_code in [301, 302, 303, 307, 308]:
            print(info + f"Redirect detected: {url} | Method: {method} | Status Code: {status_code}")
        elif status_code == 403:
            print(info2 + f"Forbidden (may indicate access control): {url} | Method: {method}")
        else:
            print(error + f"No IDOR vulnerability found for URL: {url} | "
                          f"Method: {method} | Status Code: {status_code}")

    def write_results(self, output_file):
        """Write scan results to the specified output file."""
        if not output_file or not self.results:
            return

        with open(output_file, 'w') as f:
            f.write("=" * 70 + "\n")
            f.write("IDOR SCAN RESULTS\n")
            f.write("=" * 70 + "\n\n")
            for result in self.results:
                f.write(f"URL: {result['url']}\n")
                f.write(f"Method: {result['method']}\n")
                f.write(f"Status Code: {result['status_code']}\n")
                f.write(f"Type: {result['type']}\n")
                f.write("-" * 40 + "\n")
        print(info + f"Results written to {output_file}")

    def scan(self, target_url=None):
        """
        Run the full IDOR scan on the target URL.

        Args:
            target_url (str): Override target URL (optional).
        """
        if target_url:
            self.target_url = target_url

        if not self.target_url:
            self.target_url = input(ask + "Enter Your Target's URL: ")

        self.base_url = self.target_url.rstrip('/') + '/'

        print(info + f"Starting IDOR scan on: {self.target_url}")
        print(info + "Phase 1: Crawling target...")

        # Start crawling and spidering from the initial URL
        self.crawl(self.base_url, self.base_url, depth=2)

        print(info + f"Discovered {len(self.visited_urls)} URLs")
        print(info + "Phase 2: Testing for IDOR vulnerabilities...")

        # If no URLs were discovered, still test the base URL
        if not self.visited_urls:
            self.visited_urls.add(self.base_url)

        # Make requests with different parameter values, payloads, methods and analyze
        total_tests = 0
        for url in list(self.visited_urls):
            for endpoint in self.endpoints:
                for parameter in self.parameters:
                    for value in self.test_values + self.payloads:
                        for method in self.http_methods:
                            # Craft the request URL with modified endpoint and parameter value
                            url_with_param = urljoin(url, endpoint) + "?" + parameter + "=" + value

                            status_code, response_text = self.test_request(url_with_param, method)
                            self.analyze_response(url_with_param, method, status_code, response_text)
                            total_tests += 1

        print(info + f"Scan complete. {total_tests} tests performed. "
                     f"{len(self.results)} potential vulnerabilities found.")


<<<<<<< HEAD
def main():
    """CLI entry point for IDOR scanner."""
    parser = argparse.ArgumentParser(
        description="Arachnet IDOR (Insecure Direct Object Reference) Scanner"
    )
    parser.add_argument('-u', '--url', type=str, help='Target URL to scan')
    parser.add_argument('-f', '--file', type=str,
                        help='File containing URLs to scan (one per line)')
    parser.add_argument('-o', '--output', type=str,
                        help='Output file to write results to')
    args = parser.parse_args()
=======
def main(url):
    base_url = f"{url}"
    start_url = base_url + "/"
    # Start crawling and spidering from the initial URL
    crawl(start_url, base_url)
>>>>>>> b708ea6687ccf277ffdcc35d1b3829e01d8a571d

    scanner = IDORScanner(output_file=args.output)

    if args.file:
        # Read URLs from file and scan each
        try:
            with open(args.file, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            for url in urls:
                print(info + f"\n{'=' * 50}")
                print(info + f"Scanning: {url}")
                print(info + f"{'=' * 50}\n")
                scanner.scan(url)
        except FileNotFoundError:
            print(error + f"File not found: {args.file}")
            sys.exit(1)
    elif args.url:
        scanner.scan(args.url)
    else:
        # Interactive mode
        scanner.scan()

    scanner.write_results(args.output)


if __name__ == '__main__':
<<<<<<< HEAD
    try:
        os.system("cls" if os.name == "nt" else "clear")
        main()
    except KeyboardInterrupt:
        print(f"\n{yellow}[{white}!{yellow}] {red}You Pressed Ctrl + C. Goodbye!")
=======
  try:
     os.system("clear")
     if url and not filename:
         main(url)
     else:
         urls=read(filename)
         for url in urls:
             main(url)
  except KeyboardInterrupt:
    print(error + "You Pressed Ctrl + C Goodbye!")
>>>>>>> b708ea6687ccf277ffdcc35d1b3829e01d8a571d
