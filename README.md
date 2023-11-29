# Criminal IP NSE Script

- [Description](#description)
- [About](#about)
- [Getting started](#getting-started)
- [Additional info](#additional-info)

<br/>

## Description
The NSE Script plugin integrates with Criminal IP CTI search engine for network scanning, showing IP details like WHOIS, running products, versions, CVEs, etc.

## About

### Criminal IP
Criminal IP is a comprehensive OSINT-based Cyber Threat Intelligence (CTI) providing exclusive threat information on all cyber assets. Using AI machine learning technology, it monitors open ports of IP addresses worldwide through a 24/7 scanning process and provides reports with a 5-level risk score.

### Criminal IP NSE Script
The NSE Script plugin integrated with the Criminal IP CTI search engine provides network scanning capabilities to display general information about IP addresses, including WHOIS data, running products and versions, CVE details, and more.

This plugin utilizes Port scan information from Criminal IP v1/asset/ip/report to gather information about the IP you want to scan, including WHOIS data and details about open ports.
For more details, please visit: https://www.criminalip.io/developer/api/get-asset-ip-report.



Below are the output data that you can obtain

- Hostname 
- Tag 
    - Purpose of IP usage such as VPN, Scanner, Hosting, Mobile, etc.
- Category 
    - Nature of the IP such as MISP, Phishing, Snort, Twitter, reputation, etc. 
- Country(City) 
- IP Score(Inbound/Outbound)
    - Safe, Low, Moderate, Dangerous, Critical
- Open port (within the last 30 days)
- Socket type
    - TCP, UDP
- Scan Time 
    - Date when the port was scanned
- Product 
    - Service (product) name being used on the port
- Version 
    - Product version
- CVE 
    - Vulnerabilities associated with the port (latest Top 5)

<br/>

## Getting started 

### Prerequisites
Before using the script, it is recommended to install the latest version of Nmap.

- sudo apt-get update
- sudo apt-get install nmap

You need a Criminal IP API key. You can register for a free account at [Criminal IP](https://www.criminalip.io) and find your API key on the [My Information page](https://www.criminalip.io/mypage/information.).

### Install
- - -

Copy the criminalip-api.nse script to your Nmap Script folder.

```
$ git clone https://github.com/criminalip/CIP-Nse-Script.git
$ cp criminalip-api.nse NMAP_Script_HOME(ex: /usr/share/nmap/scripts/)
```

#### API Key setting (option)
You can optionally pre-set the API key in the script to avoid entering the API key every time.

```
-- Set your Criminal IP API key here to avoid typing it in every time:
local apiKey = '${CRIMINALIP_API_KEY}'
```

<br/>

### Usage
- - -

#### The execution command

```
$  nmap --script criminalip-api --script-args 'criminalip-api.target= target IP, apikey=Your x-api-key'
$  nmap --script criminalip-api --script-args 'criminalip-api.target= target IP' # when you set your api-key on script
```

#### output
```
@output
Pre-scan script results:
| criminalip-api: 
| Result for target IP (Hostname: hostname)
| Tag: hosting, vpn, mobile
| Category: MISP, Phishing
| AS_Name: as_name
| Country: US(City: Queens) 
| Score:
|  Inbound: Critical / Outbound: Critical
| Port  Socket  Scan Time            Product        Version  CVE
| 80    tcp     2022-11-27 21:54:51  xml            1.0      
| 111   tcp     2022-11-27 13:16:11                          
| 443   tcp     2022-11-20 12:56:45  HTML 5.0                
| 53    udp     2022-12-12 08:35:18  Dnsmasq        2.40     CVE-2021-3448, CVE-2020-25687, CVE-2020-25686, CVE-2020-25685, CVE-2020-25684
| 22    tcp     2022-11-29 19:10:11  Dropbear sshd           
|_111   udp     2022-11-28 09:26:14  rpcbind        2   
```
<br/>

## Additional Info
<br/>

### Saving result to file
- - -
<br/>

You can optionally save the results in a CSV file.
> IP, Hostname, AS_Name, Country, City, Score(Inbound), Score(Outbound)

<br/>

```
nmap --script criminalip-api --script-args 'criminalip-api.target= target IP filename=test.csv'
```
<br/>

### Error Code

<br/>

Below are the descriptions for each error code 

```
- "Your CriminalIP API key is invalid": This error occurs when the API key is entered incorrectly.
- "An unexpected error occured": This error occurs when the CIP API server has failed. If you receive this error code, please try again later, or contact us at support@aispera.com.
- "The target must be an IP address": This error occurs when you enter an incorrect argument value instead of providing an IP address in the target variable.
```

