# SpyCer Domain Attack Surface Discovery
Domain Attack Surface Discovery

## **1. Overview**

The SpyCer DASD is a web-based tool developed using the Flask framework to assess and visualize the attack surface of domains or IP addresses with basic attack surface classification. It enables users to gather intelligence such as subdomains, WHOIS data, Shodan insights, and reputation checks via Spamhaus, and classifies the overall risk level. The tool aims to aid in OSINT (Open Source Intelligence) operations.


## **2. Key Functionalities**

### **2.1 Subdomain Enumeration**
- **Source**: Uses `crt.sh` (Certificate Transparency logs) via HTTPS.
- **Purpose**: Identifies known subdomains of a target domain.
- **Output**: Unique and sorted subdomain list.

### **2.2 Domain WHOIS Information**
- **Module**: `python-whois`
- **Purpose**: Retrieves registrar details, creation/expiration dates, country, and organization.
- **Use in Risk Analysis**: Assesses domain age as an indicator of potential threats (e.g., recently registered domains may pose higher risk).

### **2.3 Shodan Intelligence**
- **Service**: `Shodan API`
- **Data Collected**:
  - Open ports
  - Transport protocols for services
- **Usage**: Identifies publicly exposed services that may be vulnerable or misconfigured.

### **2.4 IP Resolution**
- **Tool**: Python `socket` module
- **Purpose**: Converts domain names into IPv4 addresses for further scanning.

### **2.5 Spamhaus DBL Check**
- **Service**: DNSBL query to `dbl.spamhaus.org`
- **Purpose**: Detects if a domain is blacklisted for spamming or malicious behavior.


## **3. Attack Surface Classification Logic**

The tool provides a basic risk classification based on combination of NIST Attack Surface Guideline and OSSTMM metric:
- **Subdomains**:
  - Low: < 3 subdomains
  - Medium: 3–5 subdomains
  - High: > 5 subdomains

- **Domain Registration Age**:
  - High Risk: < 1 year old
  - Medium Risk: 1–5 years old
  - Low Risk: > 5 years old
  - Unknown: If WHOIS data is unavailable or unparseable


## **4. Web Interface Features**

### **4.1 Frontend**
- Implemented with **HTML/CSS** embedded in `render_template_string`.
- **Input Form**: Accepts domain or IP and optional export format.
- **Dashboard Components**:
  - Info Cards (e.g., Risk Level, Subdomains)
  - Subdomains Table
  - Domain Information Panel
  - JSON Export Text Area

### **4.2 Export Functionality**
- **Format**: JSON
- **Trigger**: User selects “Export as JSON” in form.
- **Use Case**: For storing, analyzing, or integrating scan data into other systems.


## **5. Error Handling**
- Gracefully handles:
  - Invalid domain/IP inputs
  - Failed WHOIS lookups
  - Shodan API errors
  - crt.sh response failures
  - DNS resolution issues


## **6. Security & Privacy Considerations**
- **API Key Exposure**: Shodan API key is hardcoded and should be protected using environment variables.
- **Rate Limits**: Heavy use of crt.sh, Shodan, and DNSBL services may trigger abuse protections or throttling.
- **No Authentication**: The application is public by default, which may not be ideal for internal tools or sensitive operations.


## **7. Use Cases**
- Red Teaming/Blue Teaming reconnaissance
- Threat intelligence gathering
- Third-party risk assessments
- Pre-engagement scanning for ethical hacking
- SOC/IR investigation support


## **8. Limitations**
- Only resolves IPv4 addresses
- Relies heavily on third-party APIs, which may change
- WHOIS output formats vary and may affect parsing
- No backend database or logging for persistent scans

