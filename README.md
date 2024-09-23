Infogather   


Project Description

Infogather is an information gathering tool designed for cybersecurity professionals and researchers. It performs Open Source Intelligence (OSINT) activities, gathers data from various sources, and generates detailed PDF reports. This tool facilitates quick access to WHOIS, Shodan, geolocation data, and reverse IP lookup results, making it easier to analyze and interpret security-related information.
Features
    WHOIS Lookup: Retrieves domain registration details.
    Shodan Integration: Fetches information about devices connected to the internet.
    Geolocation Lookup: Locates IP addresses geographically.
    Nmap Vulnerability Scanning: Scans networks to detect vulnerabilities (coming soon on Linux).
    PDF Report Generation: Generates customizable reports for scan results.
 

Installation Instructions
Prerequisites
    Nmap: Ensure that nmap is installed, as Infogather utilizes Nmap for network scanning.
        On Linux: nmap is unavailable releasing soon
        On Windows: Download from the official website.
    Python 3.6+: Ensure that Python is installed. You can download it from here.

Install Infogather
    Clone this repository:

   bash

git clone https://github.com/htijna/Infogather.git
cd infogather

Install required dependencies:

bash

    pip install -r requirements.txt

Usage Instructions

    Command-line Interface: Run the following command to start gathering information:

    bash

    python infogather.py 
    
  Enter the ip or domain 
  
    --domain example.com

    Replace example.com with the target domain or IP address. The tool will perform WHOIS, Shodan, reverse DNS, and geolocation lookups and generate a PDF report of the results.

    PDF Report: The tool will generate a PDF report in the reports/ directory, containing the gathered information. Use the domain name to get more details than the IP address
   
Let me know if you'd like to make any changes or add more details!
!!!!Change the API key if you have a premium account

screenshots of the tool

![ss1](https://github.com/user-attachments/assets/8c09a4d2-06f7-40c0-8632-bc0a5bb937e0)


![ss2](https://github.com/user-attachments/assets/a4205b42-7439-48f3-81fc-680777905224)


![ss3](https://github.com/user-attachments/assets/5cab8a86-3683-48c0-b3a4-9220f18969a4)


PDF/result screenshot





![pg1](https://github.com/user-attachments/assets/ed8081b3-6e91-4ca2-86eb-dbe8dd95b584)

![pg2](https://github.com/user-attachments/assets/d18ff0fe-d0ad-4e4d-ac01-1a1102eda5d8)

![pg3](https://github.com/user-attachments/assets/e06c7279-d5a7-4a2e-99f6-f71921e44262)

![pg4](https://github.com/user-attachments/assets/cdab5a74-9c94-454f-8bf7-345817b8b950)

