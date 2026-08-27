# New-SSLCertificate.ps1
updated 2026-08-10  

Compatible with Powershell 5.1, and Powershell 7.0+

uses true openssl.exe

Requests new x509 certificate from local Enterprise CA server, 
and outputs certificate in all major file formats:
PEM, DER, and PFX

Browse the 'Variables' section, near line 1192, to modify
values to match your company specs.
Once variables are set, Simple usage is below:
```.\New-SSLCertificate.ps1 -FQDN 'server.company.com'
```
```.\New-SSLCertificate.ps1 -ConfigFile 'C:\path\to\config.txt'
```

openssl.exe for windows can be obtained from 'Git for Windows' or Chocolatey package manager
