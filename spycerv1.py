from flask import Flask, render_template_string, request
import requests
import shodan
import socket
import json
import whois
from datetime import datetime

app = Flask(__name__)

# Set your Shodan API Key here
SHODAN_API_KEY = "hufpgNb80LtWPVQSsIX40SgOEtJETm3s"

def get_subdomains(domain):
    """Fetch subdomains from crt.sh"""
    crt_url = f"https://crt.sh/?q={domain}&output=json"
    try:
        response = requests.get(crt_url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            subdomains = sorted(set(entry["name_value"] for entry in data))
            return subdomains
        else:
            print(f"Failed to fetch subdomains. Status code: {response.status_code}")
    except Exception as e:
        print(f"Error fetching subdomains: {e}")
    return []

def get_shodan_info(target):
    """Fetch open ports and services from Shodan"""
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        info = api.host(target)
        open_ports = info.get('ports', [])
        services = {
            port: info['data'][idx]['transport']
            for idx, port in enumerate(open_ports)
        }
        return open_ports, services
    except shodan.APIError as e:
        print(f"Shodan API error: {e}")
    return [], {}

def resolve_domain_to_ip(domain):
    """Resolve domain to IP address"""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def get_domain_info(domain):
    """Fetch domain registration information using WHOIS"""
    try:
        domain_info = whois.whois(domain)
        return domain_info
    except Exception as e:
        print(f"Failed to get domain info: {e}")
        return None

def classify_attack_surface(domain_info, subdomains):
    """Classify each attack surface component as Low, Medium, or High"""
    classification = {}
    # Subdomains classification
    sub_count = len(subdomains)
    if sub_count < 3:
        classification['Subdomains'] = "Low"
    elif 3 <= sub_count <= 5:
        classification['Subdomains'] = "Medium"
    else:
        classification['Subdomains'] = "High"
    

    # Domain Registration classification (based on domain age)
    if domain_info and domain_info.get("creation_date"):
        creation_date = domain_info.get("creation_date")
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(creation_date, str):
            try:
                creation_date = datetime.strptime(creation_date, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                try:
                    creation_date = datetime.strptime(creation_date, "%Y-%m-%d")
                except ValueError:
                    creation_date = None
        if creation_date:
            age_years = (datetime.now() - creation_date).days / 365.25
            if age_years < 1:
                classification['Domain Registration'] = "High"
            elif age_years < 5:
                classification['Domain Registration'] = "Medium"
            else:
                classification['Domain Registration'] = "Low"
        else:
            classification['Domain Registration'] = "Unknown"
    else:
        classification['Domain Registration'] = "Unknown"
    
    return classification



def check_spamhaus_dbl(domain):
    """
    Check if 'domain' is listed in the Spamhaus DBL.
    If the domain is listed, returns True (Listed), else False (Not listed).
    """
    import dns.resolver
    dbl_query = f"{domain}.dbl.spamhaus.org"
    try:
        answers = dns.resolver.resolve(dbl_query, "A")
        for rdata in answers:
            if rdata.to_text().startswith("127.0."):
                return True
        return False
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return False
    except Exception as e:
        print(f"Spamhaus check error for {domain}: {e}")
        return False

# Dashboard template with subdomain container sized
TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
  <title>SpyCer DASD</title>
  <style>
    body {
      margin: 0;
      padding: 0;
      background-color: #f2f2f2;
      font-family: Arial, sans-serif;
      color: #333;
    }
    /* Top Navbar */
    .navbar {
      background-color: #fff;
      border-bottom: 1px solid #ddd;
      padding: 15px 30px;
    }
    .navbar h1 {
      margin: 0;
      font-size: 24px;
    }

    /* Dashboard container */
    .dashboard-container {
      padding: 20px 30px;
    }

    /* Cards row */
    .cards-row {
      display: flex;
      flex-wrap: wrap;
      gap: 20px;
      margin-bottom: 20px;
    }
    .card {
      background-color: #fff;
      flex: 1 1 180px;
      min-width: 180px;
      border-radius: 4px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
      padding: 15px;
      text-align: center;
    }
    .card h2 {
      margin: 0 0 10px 0;
      font-size: 20px;
    }
    .card p {
      font-size: 24px;
      font-weight: bold;
      margin: 0;
    }


    .panel {
      background-color: #fff;
      border-radius: 4px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
      padding: 15px;
      min-width: 300px;
      flex: 1 1 300px;
    }
    .panel h3 {
      margin-top: 0;
    }
    .panel table {
      width: 100%;
      border-collapse: collapse;
      margin-bottom: 15px;
    }
    .panel th, .panel td {
      border: 1px solid #ccc;
      padding: 8px;
      text-align: left;
    }
    .panel th {
      background-color: #eee;
    }

    /* Bottom row: subdomains (left) + Export Data (JSON) (right) */
    .bottom-row {
      display: flex;
      gap: 20px;
      margin-bottom: 20px;
      flex-wrap: wrap;
    }
    .bottom-panel {
      background-color: #fff;
      border-radius: 4px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
      padding: 15px;
      min-width: 300px;
      flex: 1 1 300px;
    }
    .bottom-panel h3 {
      margin-top: 0;
    }
    .bottom-panel table {
      width: 100%;
      border-collapse: collapse;
    }
    .bottom-panel th, .bottom-panel td {
      border: 1px solid #ccc;
      padding: 8px;
    }
    .bottom-panel th {
      background-color: #eee;
    }
    textarea {
      width: 100%;
      height: 250px;
    }

    /* subdomain container for scrolling */
    .subdomain-table-container {
      max-height: 300px; /* fix the subdomains box height */
      overflow-y: auto;  /* scroll if subdomains exceed 300px */
    }

    /* Footer */
    .footer {
      text-align: center;
      color: #999;
      font-size: 14px;
      padding: 10px 0;
      border-top: 1px solid #ddd;
      background-color: #fff;
    }

    /* Form styling */
    .scan-form {
      background-color: #fff;
      border-radius: 4px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
      padding: 15px;
      margin: 20px 30px;
    }
    .scan-form label {
      font-weight: bold;
      display: block;
      margin-top: 10px;
    }
    .scan-form input[type="text"], .scan-form select {
      width: 100%;
      padding: 8px;
      margin-top: 5px;
      margin-bottom: 15px;
      box-sizing: border-box;
    }
    .scan-form input[type="submit"] {
      background-color: #4fc3f7;
      color: #fff;
      border: none;
      padding: 10px 20px;
      cursor: pointer;
      font-size: 16px;
      border-radius: 4px;
    }
    .scan-form input[type="submit"]:hover {
      background-color: #42aee4;
    }
    .error {
      color: red;
      margin-left: 30px;
    }
  </style>
</head>
<body>
<!-- Navbar -->
<div class="navbar">
  <h1>SpyCer Domain Attack Surface Discovery</h1>
</div>

<!-- Scan Form -->
<form method="post" class="scan-form">
    <label for="target">Target (Domain or Public IP):</label>
    <input type="text" id="target" name="target" required>
    
    <label for="output_format">Export Format (optional):</label>
    <select id="output_format" name="output_format">
        <option value="">None</option>
        <option value="json">JSON</option>
    </select>
    <input type="submit" value="Scan">
</form>

{% if error %}
<div class="error">{{ error }}</div>
{% endif %}

{% if result %}
<div class="dashboard-container">
  <!-- Cards Row -->
  <div class="cards-row">
    <div class="card" style="background-color: #ff7961;">
      <h2>Subdomains</h2>
      <p>{{ result.subdomains|length }}</p>
    </div>
    <div class="card" style="background-color: #81c784;">
      <h2>Risk Level</h2>
      <p>
        {{ result.attack_surface_classification['Domain Registration'] 
           if result.attack_surface_classification else 'N/A' }}
      </p>
    </div>
  </div>


    <!-- Domain Info Panel -->
    <div class="panel">
      <h3>Domain Information</h3>
      {% if result.domain_info %}
      <table>
        <tr><th>Creation Date</th><td>{{ result.domain_info.creation_date }}</td></tr>
        <tr><th>Expiration Date</th><td>{{ result.domain_info.expiration_date }}</td></tr>
        <tr><th>Registrar</th><td>{{ result.domain_info.registrar }}</td></tr>
        <tr><th>Country</th><td>{{ result.domain_info.country }}</td></tr>
        <tr><th>Owner</th><td>{{ result.domain_info.org }}</td></tr>
      </table>
      {% else %}
      <p>No WHOIS data found.</p>
      {% endif %}

      {% if result.spamhaus_status is not none %}
      <h3>Spamhaus DBL Check</h3>
      {% if result.spamhaus_status %}
        <p style="color: red; font-weight: bold;">Listed</p>
      {% else %}
        <p style="color: green; font-weight: bold;">Not Listed</p>
      {% endif %}
      {% endif %}

      <h3>Attack Surface Classification</h3>
      {% if result.attack_surface_classification %}
      <table>
        {% for component, risk in result.attack_surface_classification.items() %}
        <tr><th>{{ component }}</th><td>{{ risk }}</td></tr>
        {% endfor %}
      </table>
      {% else %}
      <p>No classification data.</p>
      {% endif %}
    </div>
  </div>

  <!-- Bottom row: subdomains (left) + Export Data (JSON) (right) -->
  <div class="bottom-row">
    <div class="bottom-panel">
      <h3>Subdomains</h3>
      <div class="subdomain-table-container">
        {% if result.subdomains and result.subdomains|length > 0 %}
        <table>
          <thead>
            <tr><th>Subdomain</th></tr>
          </thead>
          <tbody>
          {% for sub in result.subdomains %}
            <tr><td>{{ sub }}</td></tr>
          {% endfor %}
          </tbody>
        </table>
        {% else %}
        <p>No subdomains found.</p>
        {% endif %}
      </div>
    </div>

    <div class="bottom-panel">
      <h3>Export Data (JSON)</h3>
      {% if output_format == "json" and file_data %}
      <textarea readonly>{{ file_data }}</textarea>
      {% else %}
      <p>No JSON data to display.</p>
      {% endif %}
    </div>
  </div>
</div>
{% endif %}

<!-- Footer -->
<div class="footer">
  &copy; 2025 SyberSeeker
</div>
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        target = request.form.get("target")
        output_format = request.form.get("output_format")  # "json" or "csv" or empty
        
        if not target:
            return render_template_string(TEMPLATE, error="Please provide a valid domain or IP.", result=None)
        
        result = {}
        result["target"] = target
        domain_info = None
        subdomains = []
        
        # Distinguish domain from IP
        if not target.replace(".", "").isdigit():
            ip = resolve_domain_to_ip(target)
            if not ip:
                return render_template_string(TEMPLATE, error="Failed to resolve domain to IP.", result=None)
            result["resolved_ip"] = ip
            
            domain_info = get_domain_info(target)
            if domain_info:
                result["domain_info"] = {
                    "creation_date": str(domain_info.get("creation_date")),
                    "expiration_date": str(domain_info.get("expiration_date")),
                    "registrar": domain_info.get("registrar"),
                    "country": domain_info.get("country"),
                    "org": domain_info.get("org")
                }
            else:
                result["domain_info"] = None
            
            subdomains = get_subdomains(target)
            result["subdomains"] = subdomains
            
            # Spamhaus check
            spamhaus_listed = check_spamhaus_dbl(target)
            result["spamhaus_status"] = spamhaus_listed
        
        else:
            # IP
            ip = target
            result["resolved_ip"] = ip
            result["domain_info"] = None
            result["subdomains"] = []
            result["spamhaus_status"] = None
        
        # Shodan info
        open_ports, services = get_shodan_info(ip)
        result["open_ports"] = open_ports
        result["services"] = services
        
        # Classification
        classification = classify_attack_surface(domain_info, subdomains)
        result["attack_surface_classification"] = classification
        
        # Export
        file_data = None
        if output_format == "json":
            file_data = json.dumps(result, indent=4)

        
        return render_template_string(
            TEMPLATE,
            result=result,
            file_data=file_data,
            output_format=output_format,
            error=None
        )
    
    return render_template_string(TEMPLATE, result=None, file_data=None, output_format=None, error=None)

if __name__ == "__main__":
    app.run(debug=True)
