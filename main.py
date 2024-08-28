import requests
import socket
import re
import shodan
import json
from fpdf import FPDF
from tqdm import tqdm
import subprocess

import dns.resolver
import dns.reversename
import random
from bs4 import BeautifulSoup

# Replace 'YOUR_SHODAN_API_KEY' with your actual Shodan API key
SHODAN_API_KEY = 'pHHlgpFt8Ka3Stb5UlTxcaEwciOeF2QM'

# Initialize the Shodan API client
shodan_api = shodan.Shodan(SHODAN_API_KEY)

def resolve_hostname(hostname):
    """Resolve a hostname to an IP address."""
    try:
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.gaierror:
        return None

def is_ipv4(address):
    """Check if the address is an IPv4 address."""
    return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', address))

def get_ip_info_shodan(ip, history=False):
    """Retrieve information about the target IP using Shodan."""
    try:
        info = shodan_api.host(ip, history=history)
        result = f"Shodan Information for IP: {info['ip_str']}\n"
        result += f"Organization: {info.get('org', 'N/A')}\n"
        result += f"Operating System: {info.get('os', 'N/A')}\n"
        result += f"ISP: {info.get('isp', 'N/A')}\n"
        result += f"Country: {info.get('country_name', 'N/A')}\n"
        result += f"City: {info.get('city', 'N/A')}\n"
        result += f"Latitude: {info.get('latitude', 'N/A')}\n"
        result += f"Longitude: {info.get('longitude', 'N/A')}\n"
        result += "\nOpen Ports:\n"
        for item in info['data']:
            result += f"Port: {item['port']}\n"
            result += f"Service: {item.get('product', 'N/A')}\n"
            result += f"Version: {item.get('version', 'N/A')}\n"
            result += f"Banner: {item.get('data', 'N/A')}\n"
            result += "-" * 40 + "\n"
        return result
    except shodan.APIError as e:
        return f"Shodan API Error: {e}"

def get_ip_info_internetdb(ip):
    """Retrieve information about the target IP using the InternetDB API."""
    if not is_ipv4(ip):
        return "InternetDB only supports IPv4 addresses."
    
    try:
        response = requests.get(f"https://internetdb.shodan.io/{ip}")
        response.raise_for_status()
        data = response.json()

        result = f"InternetDB Information for IP: {data['ip']}\n"
        
        result += "Open Ports:\n"
        for port in data.get('ports', []):
            result += f"  - {port}\n"
        
        result += "CPEs:\n"
        for cpe in data.get('cpes', []):
            result += f"  - {cpe}\n"
        
        result += "Hostnames:\n"
        for hostname in data.get('hostnames', []):
            result += f"  - {hostname}\n"
        
        result += "Tags:\n"
        for tag in data.get('tags', []):
            result += f"  - {tag}\n"
        
        if data.get('vulns'):
            result += "Vulnerabilities:\n"
            for i, vuln in enumerate(data['vulns']):
                if i % 2 == 0:
                    result += f"{vuln:<20}"
                else:
                    result += f"{vuln}\n"
            if len(data['vulns']) % 2 != 0:
                result += "\n"
        else:
            result += "Vulnerabilities: None\n"
        
        return result.strip()
    except requests.RequestException as e:
        return f"Error fetching data from InternetDB: {e}"

def whois_lookup(target):
    """Perform WHOIS lookup using WHOIS XML API and filter the data."""
    api_key = 'at_zLKWf9TNvwGdkzu8cBNME0flQfdN3'
    url = 'https://www.whoisxmlapi.com/whoisserver/WhoisService'
    
    headers = {'Content-Type': 'application/json'}
    params = {
        'apiKey': api_key,
        'domainName': target,
        'outputFormat': 'JSON'
    }
    
    try:
        response = requests.get(url, params=params, headers=headers)
        response.raise_for_status()
        data = response.json()
        
        if 'ErrorMessage' in data:
            raise ValueError(data['ErrorMessage'])
        
        # Extract and organize the data
        domain_info = data.get('WhoisRecord', {})
        
        def get_value(key, default="Not Available"):
            """Helper function to get value from domain_info with a default."""
            return domain_info.get(key) or default
        
        def get_nested_value(keys, default="Not Available"):
            """Helper function to get nested values from domain_info."""
            value = domain_info
            for key in keys:
                value = value.get(key, {})
            return value or default
        
        report = f"""
        Domain Information
        -------------------
         Domain Name: {get_value('domainName')}
         Registrar: {get_value('registrarName')}
         Registrar IANA ID: {get_nested_value(['registryData', 'registrarIANAID'])}
         Creation Date: {get_value('createdDate')}
         Last Updated: {get_value('updatedDate')}
         Expiration Date: {get_value('expiresDate')}
         Domain Statuses:  {''.join(get_value('status', [])) or 'Not Available'}

        Registrant Information
        ----------------------
         Name: {get_nested_value(['registrant', 'name'])}
         Organization: {get_nested_value(['registrant', 'organization'])}
         Address: {get_nested_value(['registrant', 'street1'])}
         City: {get_nested_value(['registrant', 'city'])}
         State: {get_nested_value(['registrant', 'state'])}
         Postal Code: {get_nested_value(['registrant', 'postalCode'])}
         Country: {get_nested_value(['registrant', 'country'])}
         Phone: {get_nested_value(['registrant', 'telephone'])}
         Fax: {get_nested_value(['registrant', 'fax'])}
         Email: {get_nested_value(['registrant', 'email'])}

        Administrative Contact
        ----------------------
         Name: {get_nested_value(['administrativeContact', 'name'])}
         Organization: {get_nested_value(['administrativeContact', 'organization'])}
         State: {get_nested_value(['administrativeContact', 'state'])}
         Country: {get_nested_value(['administrativeContact', 'country'])}

        Technical Contact
        -----------------
         Name: {get_nested_value(['technicalContact', 'name'])}
         Organization: {get_nested_value(['technicalContact', 'organization'])}
         State: {get_nested_value(['technicalContact', 'state'])}
         Country: {get_nested_value(['technicalContact', 'country'])}

        Name Servers
        ------------
         {', '.join(get_value('nameServers', {}).get('hostNames', [])) or 'Not Available'}

        Additional Information
        ----------------------
         Domain Protection: The domain is safeguarded under multiple prohibitive statuses.
        """
        
        return report.strip()
        
    except ValueError as ve:
        return f"WHOIS lookup error: {ve}"
    except requests.exceptions.RequestException as re:
        return f"WHOIS lookup request failed: {re}"
    except Exception as e:
        return f"WHOIS lookup failed: {e}"




def reverse_dns_lookup(ip):
    """Perform reverse DNS lookup for the given IP address."""
    try:
        rev_name = dns.reversename.from_address(ip)
        reversed_dns = dns.resolver.resolve(rev_name, "PTR")
        return json.dumps([str(entry) for entry in reversed_dns], indent=4)
    except Exception as e:
        return f"Reverse DNS lookup failed: {e}"


def geolocation_lookup(ip):
    """Perform geolocation lookup for the given IP address."""
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        response.raise_for_status()
        data = response.json()

        def get_value(key):
            return data.get(key, 'Not Available')

        report = {
            "IP Information": {
                "IP": get_value('ip'),
                "Hostname": get_value('hostname'),
                "City": get_value('city'),
                "Region": get_value('region'),
                "Country": get_value('country'),
                "Location": get_value('loc'),
                "Organization": get_value('org'),
                "Postal": get_value('postal'),
                "Timezone": get_value('timezone')
            }
        }

        def format_report(report):
            formatted_report = ""
            for section, info in report.items():
                formatted_report += f"{section}\n"
                formatted_report += "-" * len(section) + "\n"
                for key, value in info.items():
                    formatted_report += f"- {key}: {value}\n"
                formatted_report += "\n"
            return formatted_report.strip()

        return format_report(report)

    except requests.RequestException as e:
        return f"Geolocation lookup failed: {e}"








def reverse_ip_lookup(ip):
    """Perform reverse IP lookup for the given IP address."""
    try:
        response = requests.get(f"http://domains.yougetsignal.com/domains.php?remoteAddress={ip}")
        data = response.json()
        return json.dumps(data.get('domainArray', []), indent=4)
    except Exception as e:
        return f"Reverse IP lookup failed: {e}"
    



# def run_nmap_scan(ip):
#     """Run an Nmap scan and return the results."""
#     try:
#         # Define the Nmap command with arguments for a fast scan
#         command = [
#             r"C:\Program Files (x86)\Nmap\nmap.exe",
#             "-sS", "-T5", "-F", "--script=vuln", "--top-ports", "10", ip
#         ]

#         # Run the Nmap command
#         result = subprocess.run(command, capture_output=True, text=True)

#         # Return the output if the command was successful
#         if result.returncode == 0:
#             return result.stdout
#         else:
#             return f"Error running Nmap: {result.stderr}"

#     except Exception as e:
#         return f"An error occurred: {str(e)}"



import subprocess

def run_nmap_scan(ip):
    """Run an Nmap scan and return the results."""
    try:
        # Define the Nmap command with arguments for a fast scan
        command = [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            "-sS", "-T5", "-F", "--script=vuln", "--top-ports", "10", ip
        ]

        # Run the Nmap command
        result = subprocess.run(command, capture_output=True, text=True)

        # Return the output if the command was successful
        if result.returncode == 0:
            return result.stdout
        else:
            return f"Error running Nmap: {result.stderr}"

    except Exception as e:
        return f"An error occurred: {str(e)}"




class CustomPDF(FPDF):
    def __init__(self, next_page_template):
        super().__init__()
        self.next_page_template = next_page_template

    def header(self):
        # Only add header on the second page and onwards
        if self.page_no() > 1:
            self.set_font('helvetica', 'B', 12)
            self.cell(0, 10, 'Scan Report', new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
            if self.next_page_template:
                self.image(self.next_page_template, x=0, y=0, w=210, h=297, type='', link='')

    def footer(self):
        self.set_y(-15)
        self.set_font('helvetica', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')

    def set_background_image(self, image_path):
        """Set background image for the current page."""
        self.image(image_path, x=0, y=0, w=210, h=297, type='', link='')

from fpdf.enums import XPos, YPos
def create_pdf(results, filename, cover_image_path, next_page_template):
    pdf = CustomPDF(next_page_template)
    
    # First page (cover page) with no text
    pdf.add_page()
    pdf.image(cover_image_path, x=0, y=0, w=210, h=297)
    
    # Start text content from the second page
    pdf.add_page()
    
    pdf.set_left_margin(20)
    pdf.set_right_margin(20)
    pdf.set_top_margin(20)
    
    heading_color = (79, 129, 189)
    
    for scan_name, content in results.items():
        # Check if there is enough space for the heading and content
        if pdf.get_y() > 250:  # Adjust if necessary
            pdf.add_page()
        
        pdf.set_font('helvetica', 'B', 14)
        pdf.set_text_color(*heading_color)
        pdf.cell(0, 10, scan_name, new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='L')
        
        pdf.set_font('helvetica', '', 12)
        pdf.set_text_color(0, 0, 0)
        
        # Add content and ensure it's on the same page as the heading if possible
        pdf.multi_cell(0, 10, content)
        
        # Optionally add some space after the content before the next heading
        pdf.ln(7)  # Adds a line break

    pdf.output(filename)
    print(f"PDF report created: {filename}")


import re

def generate_conclusion(results):
    """Generate a detailed conclusion based on the scan results."""
    conclusion = ""
    conclusion += "-" * len("Conclusion") + "\n\n"
    
    vulnerable = False  # Flag to track if any vulnerabilities are found
    
    # Nmap Scan Analysis
    if "Nmap Scan" in results:
        # Extract vulnerabilities from Nmap results
        vuln_matches = re.findall(r"VULNERABLE:\s(.*)", results["Nmap Scan"], re.IGNORECASE)
        if vuln_matches:
            conclusion += "The Nmap scan detected the following vulnerabilities:"
            for vuln in vuln_matches:
                conclusion += f"- {vuln}\n"
            conclusion += "It is crucial to patch these vulnerabilities to prevent potential exploits."
            vulnerable = True
        else:
            conclusion += "No critical vulnerabilities were detected in the Nmap scan, but regular scans are advised to ensure ongoing security."
    
    # Shodan Analysis
    if "Shodan Information" in results:
        open_ports = re.findall(r"Port:\s\d+", results["Shodan Information"])
        if open_ports:
            conclusion += f"Shodan identified {len(open_ports)} open ports, which could serve as potential entry points for attackers."
            conclusion += "It is recommended to review these open ports and secure or close them if they are not needed. Disabling unnecessary services can minimize exposure to threats."
            vulnerable = True
        else:
            conclusion += "No open ports were found at this time, reducing the risk of unauthorized access via this vector."
    
    # WHOIS Analysis
    if "WHOIS Lookup" in results:
        conclusion += "WHOIS lookup provided detailed information about the domain ownership. This information can be used to understand the entity behind the domain and assess potential risks associated with it."
    
    # Geolocation Analysis
    if "Geolocation Lookup" in results:
        location = re.search(r"Country:\s(\w+)", results["Geolocation Lookup"])
        if location and location.group(1) != "Not Available":
            conclusion += f"The IP is located in {location.group(1)}, which could indicate the origin of the services and provide insights into potential regional threats."
        else:
            conclusion += "Geolocation information was limited or not available, which could hinder efforts to determine the origin of the services."
    
    # Final Vulnerability Assessment
    if vulnerable:
        conclusion += "The system is detected as vulnerable. Immediate action is advised to mitigate the identified risks."
    else:
        conclusion += "No vulnerabilities were detected. Consider using other tools or methods, as our scan did not find any issues."

    return conclusion





def get_random_ascii_art():
    ascii_arts = [
        r"""
   .--.
  |o_o |
  |:_/ |
 //   \ \
(|     | )
/'\_   _/`\
\___)=(___/

        """,
        r"""
        / \__
       (    @\___
       /         O
      /   (_____/
/_____/   U
        """,
        r"""
        .--.  .-" "-. .    .--.
      / .. \/  .-. .-.  \/ .. \
     | |  '|  /   Y   \  |'  | |
     | \   \  \ 0 | 0 /  /   / |
      \ '- ,\.-"`` ``"-./, -' /
       `'-' /_   ^ ^   _\ '-'`
       .--'|  \._ _ _./  |'--.
     /`    \   \  __ /   /    `\
    /       '._ _ -_' _.'       \      
        """,
        r"""
        .-.
       (o o) 
        |=|
       __|__
      //.=.\\
     // .=. \\
     \\ .=. //
      \\_=_//
       (:|:)
        """
    ]
    return random.choice(ascii_arts)
from tqdm import tqdm
import time  # Used for simulating delay in the example

def run_all_scans(target, output_pdf_path, cover_image_path):
    """Run all scans and create the PDF report."""
    results = {}

    # Resolve IP address
    ip_address = resolve_hostname(target)
    if ip_address:
        results['IP Address Resolution'] = f"Resolved IP Address: {ip_address}\n"

        # List of scan functions to be performed
        scan_functions = [
            ("WHOIS Lookup", whois_lookup, target),
            ("InternetDB Information", get_ip_info_internetdb, ip_address),
            ("Geolocation Lookup", geolocation_lookup, ip_address),
            ("Shodan Information", get_ip_info_shodan, ip_address),
            ("Nmap Scan", run_nmap_scan, ip_address)
        ]
        
        # Total number of scans
        total_scans = len(scan_functions)
        
        # Initialize tqdm progress bar for scan operations
        scan_progress = tqdm(total=total_scans, desc="Running Scans", ncols=100, unit="scan")
        
        # Run each scan and update results
        for scan_name, scan_func, *args in scan_functions:
            scan_progress.set_description(f"Running {scan_name}")

            if scan_name == "Nmap Scan":
                print(f"{scan_name}ning... Great things take time.")
            
            try:
                # Execute the scan function
                results[scan_name] = scan_func(*args)
                
                # Simulate delay for demonstration (remove in real use case)
                if scan_name == "Nmap Scan":
                    time.sleep(5)  # Simulate long-running process

            except Exception as e:
                results[scan_name] = f"Error during scan: {e}"
            
            # Update the progress bar
            scan_progress.update(1)
        
        # Close the progress bar
        scan_progress.close()

        # Generate the conclusion based on the scan results
        conclusion = generate_conclusion(results)
        results["Conclusion"] = conclusion

        # Determine the next page template based on the cover page template
        template_mapping = {
            "img/cover1.jpg": "img/cover2.jpg",
            "img/page1.jpg": "img/page2.jpg",
            "img/set1.jpg": "img/set2.jpg"
        }
        
        next_page_template = template_mapping.get(cover_image_path, None)

        # Create the PDF with all the results
        create_pdf(results, output_pdf_path, cover_image_path, next_page_template)
    else:
        print(f"Error: Unable to resolve the IP address for {target}")

def main():
    """Main function to execute the script."""
    selected_art = get_random_ascii_art()
    print(selected_art)
    
    target = input("Enter IP address or domain name to scan: ")
    
  
    # Select a random cover page image
    cover_images = ["img/cover1.jpg", "img/page1.jpg", "img/set1.jpg"]  # Add your image paths here
    cover_image_path = random.choice(cover_images)
    
    # Determine the next page template
    next_page_template = {
        "img/cover1.jpg": "img/cover2.jpg",
        "img/page1.jpg": "img/page2.jpg",
        "img/set1.jpg": "img/set2.jpg"
    }.get(cover_image_path, None)
    pdf_filename = f"{target}_report.pdf"
    run_all_scans(target, pdf_filename, cover_image_path)
    
if __name__ == "__main__":
    main()