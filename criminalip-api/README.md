# Criminal IP NSE Script

Korean: [README.kor.md](README.kor.md)
<br>
Japanese: [README.jpn.md](README.jpn.md)

- [Description](#description)
- [Getting started](#getting-started)
- [Additional info](#additional-info)

<br/>

## Description
The following script links Criminal IP API to the Nmap script, allowing you to obtain information about IP.

Returned Data Info

- Hostname 
- Tag info
    - IP Usage: VPN, Scanner, Hosting, Mobile  etc.
- Category 
    - IP Category: MISP, Phishing, Snort, Twitter, reputation etc.
- Country(City) 
- IP Score(Inbound/Outbound)
    - Safe, Low, Moderate, Dangerous, Critical
- Currently opened Port (in the last 60 days)
- Socket type
    - TCP, UDP
- Scan Time 
    - Date of port scan
- Product 
    - Service used on Port
- Version 
    - Product version
- CVE 
    - Vulnerabilities found in Port (Latest Top 5)

<br/>

## Getting started 
<br/>

### Install
- - -

Copy the criminalip-api.nse script to your Nmap Script folder.

```
$ git clone https://github.com/criminalip/CIP-Nse-Script.git
$ cp criminalip-api.nse NMAP_Script_HOME(ex: /usr/share/nmap/scripts/)
```
<br/>

### Usage
- - -

Please follow these two steps before using this service.

1. Create an API Key by signing up for [Criminal IP](https://www.criminalip.io/ko)

2. You can enter your API key into the script file so that you don’t have to enter the API Key every time. (Optional)

```
-- Set your Criminal IP API key here to avoid typing it in every time:
local apiKey = ""
```

The example below shows the results of searching for IP through script file. You can find various information such as risk score, country information, as_name for specific IP addresses.
```
$  nmap --script criminalip-api --script-args 'criminalip-api.target= target IP, apikey=Your x-api-key'
$  nmap --script criminalip-api --script-args 'criminalip-api.target= target IP' # when you set your api-key on script

@output
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

You can use the filename script argument to save some results as a CSV file.
> IP, Hostname, AS_Name, Country, City, Score(Inbound), Score(Outbound)

<br/>

```
nmap --script criminalip-api --script-args 'criminalip-api.target= target IP filename=test.csv'
```
<br/>

### Error Code

<br/>

You may receive 1 of the following three error messages.

- Your Criminal IP API key is invalid.

- An unexpected error occurred.

- The target must be an IP address.

The first error message is when the API key is inputted incorrectly.
 
The second error message is when there is an error with the CIP API server. 
> Should this occur, please try again later or contact support@aispera.com.
 
The third error message occurs when an invalid argument with no valid IP in the target variable is delivered.
