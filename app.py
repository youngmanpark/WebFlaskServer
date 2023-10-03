import json

from flask import Flask, request, jsonify
import requests

from WebVulnerabilties import return_json_data
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
app.config['JSON_AS_ASCII'] = False

def private_to_public_ip(private_ip):
    response = requests.get("https://api.ipify.org?format=json")
    if response.status_code == 200:

        public_ip = response.json()["ip"]
        return public_ip
    else:
        return None

@app.route('/vulnerabilities', methods=['GET','POST'])
def get_result_api():
    url_parameter = request.get_json()
    url=url_parameter.get('url')
    # url=private_to_public_ip(url)

    result=return_json_data(url)

    return result

@app.route('/checkvulnerabilities', methods=['GET','POST'])
def get_result_api2():

    url = request.form.get('url')
    url= str(url)
    print(url)
    result= return_json_data(url)
    # url=private_to_public_ip(url)
#     result=[
#     {
#         "vulnerability": "Check CVE",
#         "description": "Common Vulnerabilities and Exposures (CVE) is a list of publicly known computer security flaws. CVE usually refers to a security flaw assigned a CVE ID number.",
#         "purpose": "It aims to standardize the way known vulnerabilities are identified. Standard IDs help security managers find and utilize technical information about specific threats from many different sources of CVE support information.",
#         "security_threat": "A publicly known computer security flaw (CVE) based on header information from that server",
#         "content": "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=nginx/1.18.0",
#         "status": "Risk"
#     },
#     {
#         "vulnerability": "Admin Page",
#         "description": "Check whether the admin page and menu access is possible with an easy-to-infer URL",
#         "purpose": "To prevent unauthorized persons from accessing the admin menu by correcting the easy-to-understand names (admin, manager, etc.) of the admin page URL and website design errors",
#         "security_threat": "If the authority of the web administrator is exposed, not only the modification of the website but also the authority of the web server may be exposed depending on the degree of vulnerability.",
#         "content": "no admin page found",
#         "status": "Safe"
#     },
#     {
#         "vulnerability": "Cleartext Transmission ",
#         "description": "Whether or not the server verifies communication between the server and the client",
#         "purpose": "To prevent the risk of information leakage due to insufficient data encrypted transmission during communication between the server and the client",
#         "security_threat": "Since data communication on the web is mostly text-based, information can be stolen and stolen through simple sniffing if an encryption process is not implemented between the server and the client.",
#         "content": "Port 80 does not support encryption (TLS/SSL).",
#         "status": "risk"
#     },
#     {
#         "vulnerability": "XSS Injection",
#         "description": "Check for cross-site scripting vulnerabilities in your website",
#         "purpose": " Block malicious script execution by removing cross-site scripting vulnerabilities in websites",
#         "security_threat": "If filtering of user input values ​​is not properly performed in web applications, an attacker inserts malicious scripts (Javascript, VBScript, ActiveX, Flash, etc.) Cookies (session) can be hijacked and stolen or redirected to malicious code distribution sites",
#         "content": "Not detected WEAKNESS about XSS",
#         "status": "Safe"
#     },
#     {
#         "vulnerability": "SQL Injection",
#         "description": "Checks for SQL injection vulnerabilities in web pages",
#         "purpose": "To prevent malicious database access and manipulation by blocking abnormal user input values ​​on interactive websites",
#         "security_threat": "An attack that takes advantage of the weakness that website SQL queries are completed with user input values, and combines or executes abnormal SQL queries by tampering with input values. It is possible to manipulate the database abnormally by causing the developer to execute unexpected SQL statements.",
#         "content": "Not Detected WEAKNESS about sql Injection!",
#         "status": "safe"
#     },
#     {
#         "vulnerability": "Directory Indexing",
#         "description": "Checking for directory indexing vulnerabilities in the web server",
#         "purpose": "Block exposure of unnecessary file information in a specific directory by removing directory indexing vulnerabilities",
#         "security_threat": " A vulnerability that automatically displays a directory list when files of the initial page (index.html, home.html, default.asp, etc.) do not exist in a specific directory.",
#         "content": "This website is SAFE from Directory listing",
#         "status": "Safe"
#     }
# ]


    return result


if __name__ == '__main__':
    app.run('0.0.0.0', port=3333, debug=True)
