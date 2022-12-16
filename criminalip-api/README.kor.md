# Criminal IP NSE Script

- [Description](#description)
- [Getting started](#getting-started)
- [Additional info](#additional-info)

<br/>

## Description
해당 스크립트는 Criminal IP API를 Nmap Script에 연동하여 IP에 대한 정보를 얻을 수 있습니다. 

반환되는 데이터 정보

- Hostname 
- Tag 
    - VPN, Scanner, Hosting, Mobile 등의 IP 사용 목적
- Category 
    - MISP, Phishing, Snort, Twitter, reputation 등의 IP 성격
- 국가(도시) 
- IP 스코어(인바운드/아웃바운드)
    - Safe, Low, Moderate, Dangerous, Critical
- 열려있는 Port (60일 기준)
- Socket type
    - tcp, udp
- Scan Time 
    - 포트가 스캔 된 날짜
- Product 
    - 포트에서 사용되고 있는 서비스(제품)명
- Version 
    - 제품의 버전
- CVE 
    - 포트가 가지고 있는 취약점 (최신 Top 5)

<br/>

## Getting started 
<br/>

### Install
- - -

criminalip-api.nse script를 당신의 Nmap Script 폴더로 복사합니다.

```
$ git clone https://github.com/criminalip/CIP-Nse-Script.git
$ cp criminalip-api.nse NMAP_Script_HOME(ex: /usr/share/nmap/scripts/)
```
<br/>

### Usage
- - -

사용 하기에 앞서 2개의 작업이 필요합니다.

1. [Criminal IP](https://www.criminalip.io/ko)에 가입 후 API-Key를 생성해야 합니다. 

2. 매번 API-Key를 입력하지 않도록 Script에 API-Key를 입력해 놓을 수 있습니다.(선택)

```
-- Set your Criminal IP API key here to avoid typing it in every time:
local apiKey = ""
```

아래 예제는 스크립트를 통해 IP를 검색한 결과입니다. 해당 IP 주소에 대한 점수, 국가 정보, as_name 등 여러 정보들을 확인할 수 있습니다. 
```
$  nmap --script criminalip-api --script-args 'criminalip-api.target= target IP, apikey=Your x-api-key'
$  nmap --script criminalip-api --script-args 'criminalip-api.target= target IP' # when you set your api-key on script

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

**filename** 스크립트 인수를 사용하여 결과의 일부를 csv 파일로 저장할 수 있습니다.  
> IP, Hostname, AS_Name, Country, City, Score(Inbound), Score(Outbound)

<br/>

```
nmap --script criminalip-api --script-args 'criminalip-api.target= target IP filename=test.csv'
```
<br/>

### Error Code

<br/>

3개의 에러 메시지가 존재합니다. 

- Your CriminalIP API key is invalid.

- Unexpected error occured 

- target must be an IP address

</br>


첫 번째 에러 메시지는 API-Key를 잘못 입력하는 경우 입니다. 

두 번째 에러 메시지는 CIP API 서버에 장애가 발생 했을 경우 입니다.
> 해당 에러가 발생 시 잠시 후 시도하거나 support@aispera.com 으로 문의 부탁드립니다. 

세 번쨰 에러 메시지는 target 변수에 IP를 넣지 않고 잘못된 인자값을 전달한 경우 입니다.