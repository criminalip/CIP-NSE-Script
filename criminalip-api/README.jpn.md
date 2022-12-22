# Criminal IP NSE Script

- [Description](#description)
- [Getting started](#getting-started)
- [Additional info](#additional-info)

<br/>

## Description
このスクリプトで Criminal IP APIを Nmap Script に連動し、IP に関する情報を得られます。


リターンされるデータ情報

- Hostname 
- Tag 
    - VPN, リターンされるデータ情報
- Category 
    - MISP, フィッシング、Snort、Twitter、レピュテーションなどの IP 特徴
- 国（都市 
- IP スコア（インバウンド・アウトバウンド）
    - Safe, Low, Moderate, Dangerous, Critical
- 開いているポート（60日を基準とする
- Socket type
    - tcp, udp
- Scan Time 
    - ポートがスキャンされた日付
- Product 
    - ポートで使用されるサービス（製品）名
- Version 
    - 製品のバージョン
- CVE 
    - ポートにある脆弱性（最新 Top 5)

<br/>

## Getting started 
<br/>

### Install
- - -

criminalip-api.nse script を自分の Nmap Script フォルダーにコピーします。

```
$ git clone https://github.com/criminalip/CIP-Nse-Script.git
$ cp criminalip-api.nse NMAP_Script_HOME(ex: /usr/share/nmap/scripts/)
```
<br/>

### Usage
- - -

使用に先立って、2つの作業が必要です。

1. [Criminal IP](https://www.criminalip.io/ko)に会員登録する後、APIキーを生成します。 

2. 毎回 APIキーを入力しなくても済むように、Scriptに APIキーを入力しておくことができます。（選択)

```
-- Set your Criminal IP API key here to avoid typing it in every time:
local apiKey = ""
```

下の例はスクリプトを通じてIPを検索した結果です。該当IPアドレスに関するスコア、国家情報、as_nameなどの様々な情報を確認できます。
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

**filename** スクリプトの引数を用いて結果の一部を csv ファイルとして保存することができます。
> IP, Hostname, AS_Name, Country, City, Score(Inbound), Score(Outbound)

<br/>

```
nmap --script criminalip-api --script-args 'criminalip-api.target= target IP filename=test.csv'
```
<br/>

### Error Code

<br/>

3つのエラーメッセージがあります。

- Your CriminalIP API key is invalid.

- An unexpected error occured 

- The target must be an IP address

</br>


1つ目のエラーメッセージは APIキーを間違えて入力した場合に表われます。 

2つ目のエラーメッセージは Criminal IP API サーバーに障害が発生した場合に表われます。
> このエラーが発生する場合、しばらくしてもう一度試みるかまたは、 support@aispera.com よりお問い合わせお願いいたします。

3つ目のエラーメッセージは target 変数に IP を入力せず、間違えた引数を入れた場合に表われます。