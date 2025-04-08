# SpyCer Domain Attack Surface Discovery
Domain Attack Surface Discovery

## **1. Overview**
The SpyCer DASD is a web-based tool developed using the Flask framework to assess and visualize the attack surface of domains or IP addresses with basic attack surface classification. It enables users to gather intelligence such as subdomains, WHOIS data, Shodan insights, and reputation checks via Spamhaus, and classifies the overall risk level. The tool aims to aid in OSINT (Open Source Intelligence) operations.

## **2. Key Functionalities**

### **2.1 Subdomain Enumeration**
- Uses **crt.sh** for retrieving certificate transparency logs.
- Detects and lists associated subdomains.

### **2.2 WHOIS Information**
- Retrieves domain registration details including creation and expiration dates, registrar, country, and organization.

### **2.3 Shodan Integration**
- Queries the **Shodan API** to retrieve open ports and running services.
- Helps identify exposed network surfaces.

### **2.4 DNS Resolution**
- Resolves domains to IPv4 addresses using the built-in `socket` module.

### **2.5 Spamhaus DBL Check**
- Uses DNS queries to determine if a domain is blacklisted for spam or malicious activity.

## **3. Attack Surface Classification**
The tool provides a basic risk classification based on combination of NIST Attack Surface Guideline and OSSTMM metric:
| Component            | Risk Level Criteria                     |
|---------------------|------------------------------------------|
| Subdomains          | Low (< 3), Medium (3–5), High (> 5)      |
| Domain Age          | Low (> 5 yrs), Medium (1–5 yrs), High (< 1 yr) |


## **4. Web Interface Overview**

- Clean, responsive HTML/CSS layout
- Key elements:
  - Input form for domain/IP
  - Cards for subdomain count and risk level
  - Domain WHOIS panel
  - Subdomain table with scroll support
  - JSON export option

## **5. Error Handling**

The tool gracefully manages various failure points:
- Invalid domain/IP inputs
- Unresolved domains
- API call failures (WHOIS, Shodan, crt.sh)
- DNS query errors

## **6. Installation Guide**

### **6.1 Prerequisites**
Ensure you have the following installed:
- **Python 3.7+**
- **pip** (Python package manager)

### **6.2 Clone the Repository**
If the script is in a Git repository:
```bash
git clone https://github.com/syberseeker/SpyCer-Domain-Attack-Surface-Discovery/spycer-dasd.git
cd spycer-dasd
```
If it’s a standalone `.py` file, just place it in your working directory.

### **6.3 Install Required Packages**
You can install dependencies via pip:
```bash
pip install flask requests shodan python-whois dnspython
```

### **6.4 Set Your Shodan API Key**
The script currently hardcodes the API key:
```python
SHODAN_API_KEY = "your-api-key-here"
```
> 🔒 **Security Tip**: Replace this with an environment variable for better security.

Example:
```python
import os
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
```
And in your terminal:
```bash
export SHODAN_API_KEY=your_key
```

### **6.5 Run the Application**
```bash
python spycerv1.py
```

Then open your browser and navigate to:
```
http://127.0.0.1:5000/
```

## **7. Use Cases**
- Penetration testing reconnaissance
- Threat intelligence
- Red team assessments
- SOC enrichment
- Suspicious domain analysis

## **8. Current Limitation**
- No IP geolocation support
- No persistent database
- Assumes IPv4 resolution
- WHOIS parsing may fail on complex registrars

## **9. Output Sample**
**Domain Information, Spamhaus Check and Attack Surface Classification**

![Screenshot 2025-04-08 143529](https://github.com/user-attachments/assets/975a1957-002b-4a63-9490-a62206277006)

**Subdomains Result and Export Data (JSON)**

![Screenshot 2025-04-08 150514](https://github.com/user-attachments/assets/220a3a8a-347c-44d5-81b4-ffed1c7ae0d9)


# Version

**v1.0 SpyCer DASD (2025-04-08)**
- Subdomain Enumeration
- WHOIS Information
- DNS Resolution
- Spamhaus DBL Check
- Support export format in CSV and JSON format

# Next Roadmap v2.0

- Adding capability to choose attack surface scoring
- Extending more domain blacklist check sources



