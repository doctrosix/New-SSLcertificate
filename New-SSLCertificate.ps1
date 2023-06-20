# New-SSLCertificate v20230620.01
#
# if you have a local Root CA, please place a PEM copy of the public root cert chain in the same folder as the script
# Browse the 'Set Variables' section to modify values to match your company specs.
# Once variables are set, Simple usage is below:
#       .\New-SSLCertificate.ps1 -FQDN 'server.company.com'
#

[CmdletBinding()]
param(
    # Required IF no config file present.
    [string]$FQDN = '',
    # Required IF no FQDN submitted. Will take an OpenSSL config file if you have one.
    [string]$ConfigFile = 'C:\falsefolderName\9824357039487.txt',
    # Optional. Organization Name (Company Name)
    # set default name in 'Set Variables > Org Handling' below.
    [string]$Org = '',
    ####
    # Optional. please submit extra FQDNs in quotes separated by commas.
    # accepts arrays.
    # Example:
    #		-ExtraSANs "app.company.com", "db.company.com", "db"
    # Defaults:
    #       host.company.com.
    #       www.host.company.com.
    #       host. (only if Local CA)
    ####
    [string[]]$ExtraSANs = @(),
    # Optional. Will ask you for a password if no SecureString is provided
    [securestring]$NewPassword = (
        Read-Host -Prompt "Enter password for private Key and PFX file" -AsSecureString
    ),
    # Optional. Will create a new folder based on timestamp
    [string]$WorkFolderName = '',
    # Optional. For use with Public CA like Digicert, Entrust, etc.
    # if param is unused it defaults to Local-CA submission.
    # Uses Chain file you provided. please edit $caChainFile with your rootchain file name.
    [switch]$forPublicCAsigning,
    # Optional. Packs an additional PFX with key and cert only. No chains included in PFX.
    # (useful for copiers and printers)
    [switch]$basicPFX
)

####
#	Param error handling
####
$noFQDNparam = $FQDN -ceq ''
$noConfigFileParam = $ConfigFile -ceq 'C:\falsefolderName\9824357039487.txt'
if ($noFQDNparam -and $noConfigFileParam) {
    throw "ERROR: Must provide full FQDN, or openSSL config file"
}

#####################################################################################
# Set Variables
#####################################################################################
#       Copy your Enterprise CA cert chain to the script's home folder, in PEM / Base64 format
#       Edit $caChainFile below to match your rootchain PEM file.
#####################################################################################
$caChainFile = Join-Path -Path $PSScriptRoot -ChildPath "localCA-RootChain.crt"

# Windows CA server: caserver.company.com\CAname
$companyCAfqdn = 'ca01.company.com'
$companyCAname = 'Company-CA01-CA'
$companyCA = $companyCAfqdn + '\' + $companyCAname
$certTemplate = 'Company-WebServer'

$configFileExists = Test-Path -Path $ConfigFile

# check if OpenSSL is installed locally
$openSSL = "C:\Program Files\Git\usr\bin\openssl.exe"
$gitNotInstalled = -not (Test-Path -Path $openSSL)
if ( $gitNotInstalled ) {
    "You need OpenSSL from Git installed on your machine"
    "Please install Git for Windows at https://git-scm.com/"
    Throw "Git not installed"
}

$config = 'config.txt'
$key = 'key.pem'
$keyplain = 'keyplain.pem'
$keypass = 'keypass.txt'
$csr = 'signrequest.csr'
$cert = 'cert.crt'
$chain = 'chain.crt'
$fullchain = 'fullchain.crt'
$pfx = 'pack.pfx'
$basicPFXfile = 'basic.pfx'
$pfxpass = 'pfxpass.txt'

# Sets $LocalCACert flag
if ($forPublicCAsigning) {
    $LocalCACert = $false
}
else {
    $LocalCACert = $true	
}

# FQDN handling
if ($configFileExists) {
    # Do Nothing, $FQDN ignored.
}
elseif ($FQDN -eq '') {
    $FQDN = Read-Host -Prompt "Enter FQDN"
}
else {
    # Do Nothing
}

# Org Handling
if ($LocalCACert) {
    $Org = 'Company Co.'
}
elseif ($Org -eq '') {
    $Org = Read-Host -Prompt "Enter Company Name"
}

#####################################################################################
## FUNCTIONS
#####################################################################################
# Decrypts SecureStrings to Strings for feeding OpenSSL.exe, and TXT files.
function Format-SecureString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [securestring]$SecString
    )

    [string]$plaintext = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR( $SecString )
    )

    return $plaintext
}

# Generates OpenSSL config file
function New-ConfigContent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$FQDN,
        [Parameter(Mandatory = $false)] [string[]]$ExtraSANs = @(),
        [Parameter(Mandatory = $true)] [string]$Org,
        [Parameter(Mandatory = $false)] [bool]$PublicCA = $false
    )
	
    $domainsplit = $FQDN.Split('.')
    $netBIOShostname = $domainsplit[0]
    $domainlevels = $domainsplit.Length
    [string[]]$basicSANs = @(
        'DNS:$FQDN'
        if ( $FQDN -match '/*' ) {
            # wildcard certs
            # if FQDN is '*.company.com', this outputs 'DNS:company.com'
            (
                'DNS:' + (
                    @($domainsplit[1..($domainlevels - 1)]) -Join '.'
                )
            )
        }
        else {
            # Non-wildcard certs
            # Adds basic SANs for deployment flexibility
            #       IF $FQDN equals 'server.company.com'
            #       THEN it adds:
            #           www.server.company.com.
            #           server.
            # The single-word netbios name is disabled for Public CA submission
            'DNS:www.$FQDN'
            if (-not $PublicCA) {
                ('DNS:' + $netBIOShostname)
            }
        }
    )

    # Assemble Subject Alternative Name string
    if ( $ExtraSANs.Length -gt 0 ) {
        [string[]]$formattedSANs = @(
            foreach ( $san in $ExtraSANs ) {
                'DNS:' + $san
            }
        )
        [string]$altSANs = ( $basicSANs + $formattedSANs ) -join ', '
    }
    else {
        [string]$altSANs = $basicSANs -join ', '
    }

    # Create config.txt content
    # req_distinguished_name should be ordered big to small
    # Example: Country, State, Locality (City), Org, OU, Common Name (FQDN)
    # C, S, L, O, OU, CN
    #
    $configContent = @(
		('FQDN = ' + $fqdn)
		('ORGNAME = ' + $Org)
		('ALTNAMES = ' + $altSANs)
        ''
        "[ req ]"
        "default_bits = 2048"
        "default_md = sha256"
        "prompt = no"
        "encrypt_key = no"
        "distinguished_name = req_distinguished_name"
        "req_extensions = req_ext"
        ''
        "[ req_distinguished_name ]"
        "C = US"
        'O = $ORGNAME'
        'CN = $FQDN'
        ''
        "[ req_ext ]"
        'subjectAltName = $ALTNAMES'
    )
    return $configContent
}

# Hashes the Modulus Strings
function Start-ModulusHash {
    [CmdletBinding()]
    param(
        [string]$String
    )
	
    $stringAsStream = [System.IO.MemoryStream]::new()
    $writer = [System.IO.StreamWriter]::new($stringAsStream)
    $writer.Write($String)
    $writer.Flush()
    $stringAsStream.Position = 0
    $hash = (Get-FileHash -InputStream $stringAsStream -Algorithm SHA256).Hash
    return $hash
}

# Submits CSR to Windows CA server using certreq
# User must be permitted to enroll certificates within template permissions
function Send-CSRtoCompanyCA {
    [CmdletBinding()]
    param(
        [string]$WindowsCA,
        [string]$CSRfilePath,
        [string]$CertFilePath,
        [string]$Template
    )

    # Submit CSR to CA. Then save cert File and CA response.
    $attrib = 'CertificateTemplate:' + $Template
    $certReqOutput = & 'C:\Windows\system32\certreq.exe' '-submit' '-attrib' "`"$attrib`"" '-config' "`"$WindowsCA`"" "`"$CSRfilePath`"" "`"$CertFilePath`""
    $certIssued = $certReqOutput[2] -eq 'Certificate retrieved(Issued) Issued'
    if ($certIssued) {
        # do nothing
    }
    else {
        $certReqOutput
        Throw "ERROR: Certificate not issued"
    }
    # Process CA response file into readable Text.
    $certFileObj = Get-Item -Path $CertFilePath
    $certFolderPath = $certFileObj.DirectoryName
    $responseFilePath = Join-Path -Path $certFolderPath -ChildPath ($certFileObj.BaseName + '.rsp')
    $responseTXTfilePath = Join-Path -Path $certFolderPath -ChildPath '.\CAresponse.txt'
    & 'C:\Windows\System32\certutil.exe' "`"$responseFilePath`"" > $responseTXTfilePath
    Remove-Item -Path $responseFilePath
    return $true
}

#####################################################################################
# MAIN
#####################################################################################
''
####
# Create and enter Workfolder
####

# Create Workfolder
if ( $workFolderName -eq '' ) {
    [string]$workFolderName = (Get-Date -Format FileDateTime).Substring(0, 15)
}
[string]$workFolder = ( New-Item -Path $workFolderName -ItemType Directory ).FullName

# prepare Path strings for each workfile.
$config = Join-Path -Path $workFolder -ChildPath $config
$key = Join-Path -Path $workFolder -ChildPath $key
$keyplain = Join-Path -Path $workFolder -ChildPath $keyplain
$keypass = Join-Path -Path $workFolder -ChildPath $keypass
$csr = Join-Path -Path $workFolder -ChildPath $csr
$cert = Join-Path -Path $workFolder -ChildPath $cert
$chain = Join-Path -Path $workFolder -ChildPath $chain
$fullchain = Join-Path -Path $workFolder -ChildPath $fullchain
$pfx = Join-Path -Path $workFolder -ChildPath $pfx
$pfxpass = Join-Path -Path $workFolder -ChildPath $pfxpass
$basicPFXpath = Join-Path -Path $workFolder -ChildPath $basicPFXfile

$workFolderReady = Test-Path -Path $workFolder
$tryCount = 0
while ( -not $workFolderReady ) {
    Start-sleep -Seconds 5
    $workFolderReady = Test-Path -Path $workFolder
    $tryCount ++
    if ($tryCount -ge 12) { Throw 'Workfolder cannot be created' }
}

Set-Location -Path $workFolder

if ($LocalCACert) {
    Copy-Item -Path $caChainFile -Destination $chain
}

# If no $ConfigFile is supplied, generate basic config file.
if ($configFileExists) {
    $content = Get-Content -Path $ConfigFile
    Set-Content -Value $content -Path $config
}
else {
    if ($forPublicCAsigning) {
        $content = New-ConfigContent -FQDN $FQDN -ExtraSANs $ExtraSANs -Org $Org -PublicCA $forPublicCAsigning
    }
    else {
        $content = New-ConfigContent -FQDN $FQDN -ExtraSANs $ExtraSANs -Org $Org
    }
    Set-Content -Value $content -Path $config
}

# Create plaintext private Key and CSR files
'*** Creating keypair and CSR...'
$openSSLargs = @(
    'req',
    '-new',
    '-config', "`"$config`"",
    '-keyout', "`"$keyplain`"",
    '-out', "`"$csr`""
)
& $openSSL $openSSLargs
Remove-Variable -Name 'openSSLargs'
'DONE'
''

# Create a password-protected private key file for systems that need it
'*** Encrypting private key'
$openSSLargs = @(
    'rsa',
    '-des',
    '-in', "`"$keyplain`"",
    '-passout', (
        'pass:' + (
            Format-SecureString -SecString $NewPassword
        )
    ),
    '-out', "`"$key`""
)
& $openSSL $openSSLargs
Remove-Variable -Name 'openSSLargs'
'DONE'
''

# Create txt file containing password
Set-Content -Value ( Format-SecureString -SecString $NewPassword ) -Path $keypass

####
# Submit CSR and get signed cert.
####
if ($LocalCACert) {
    #"-Visit the Local CA at https://pki.peerlessbev.com/certsrv and submit the CSR."
    '*** Submitting CSR to ' + $companyCA + '...'
}
else {
    "-Visit your SSL vendor website and submit the CSR."
    "-Please download PEM, or Base64 format files from the signing CA"
    "-Use the file saved as signrequest.csr or use the Text Below:"
    ''

    # outputs CSR text to screen.
    $csrdata = Get-Content -Path $csr
    $csrdata
    ''
    $csrdata | Set-Clipboard
    "Text Copied to Clipboard"
    ''
}

if ($LocalCACert) {
    # Do Nothing
}
else {
    "-Copy the vendor's signed certificate file, and chain file to the work folder:"
    ( '    ' + $workFolder )
    ''
}

[bool]$localCAcertHasBeenIssued = $false
if ($LocalCACert) {
    $parameters = @{
        WindowsCA = $companyCA
        CSRfilePath = $csr
        CertFilePath = $cert
        Template = $certTemplate
    }
    $localCAcertHasBeenIssued = Send-CSRtoCompanyCA @parameters
    $SignedCertFile = 'cert.crt'
}
else {
    ''
    "-Fill in the blanks below when you're ready"
    ''
    $SignedCertFile = Read-Host -Prompt "Enter cert file name"
    ''
}

if ($localCAcertHasBeenIssued) {
    "SUCCESS: Certificate Issued"
    ''
}

if ( -not $LocalCACert ) {
    $chainfile = Read-Host -Prompt "Enter chain or bundle file name"
}

if ( $SignedCertFile -cne 'cert.crt' ) {
    Copy-Item -Path ( '.\' + $SignedCertFile ) -Destination ( $cert )
}
if ( -not $LocalCACert ) {
    if ( $chainfile -cne 'chain.crt' ) {
        Copy-Item -Path ( '.\' + $chainfile ) -Destination ( $chain )
    }
}


#Check Cert Chain
"*** Testing certificate against CA chain..."
$openSSLargs = @(
    'verify',
    '-x509_strict',
    '-CAfile', "`"$chain`"",
    "`"$cert`""
)
[string]$chainTestOutput = (& $openSSL $openSSLargs).Trim()
$chainTestOutput
[string]$chainTest = $chainTestOutput.Substring($chainTestOutput.Length - 2)
if ( $chainTest -ceq 'OK') {
    "PASSED: Certificate chain is valid"
    ''
}
else {
    Set-Location -Path '..'
    Throw "FAILED: Cert does not link to chain."
}

# Assemble Full Certificate chain file, fullchain.crt
$fullChainData = Get-Content -Path @(
    $cert
    $chain
)
$fullChainData | Set-Content -Path $fullchain

####
#	Check Key against Fullchain Cert
####
"*** Testing private key against full certificate chain..."

# Getting modulus from fullchain
$openSSLargs = @(
    'x509',
    '-noout',
    '-modulus',
    '-in', "`"$fullChain`""
)
[string]$openSSLOutput = & $openSSL $openSSLargs
[string]$certModulus = $openSSLOutput.Trim().Split('=')[1]
$certHash = Start-ModulusHash -String $certModulus
('Hash of cert modulus: ' + $certHash)

# Getting modulus from private key
$openSSLargs = @(
    'rsa',
    '-noout',
    '-modulus',
    '-in', "`"$keyplain`""
)
[string]$openSSLOutput = & $openSSL $openSSLargs
[string]$keyModulus = $openSSLOutput.Trim().Split('=')[1]
$keyHash = Start-ModulusHash -String $keyModulus
('Hash of key modulus:  ' + $keyHash)

if ( $certHash -ceq $keyHash ) {
    "PASSED: Key matches certificate and chain"
    ''
    ''
}
else {
    Set-Location -Path '..'
    Throw "key does not match certificate"
}

####
# packing the the PFX file(s)
####
# Packs key, cert, and CA chain.
$openSSLargs = @(
    'pkcs12',
    "-export",
    '-inkey', "`"$keyplain`"",
    "-in", "`"$cert`"",
    "-certfile", "`"$chain`"",
    "-out", "`"$pfx`"",
    "-passout", ( "pass:" + (Format-SecureString -SecString $NewPassword) )
)
& $openSSL $openSSLargs

if ($basicPFX) {
    # Packs key and cert only. (useful for copiers and printers)
    $openSSLargs = @(
        'pkcs12',
        "-export",
        '-inkey', "`"$keyplain`"",
        "-in", "`"$cert`"",
        "-out", "`"$basicPFXpath`"",
        "-passout", ( "pass:" + (Format-SecureString -SecString $NewPassword) )
    )
    & $openSSL $openSSLargs
}

Remove-Variable -Name 'openSSLargs'
( Format-SecureString -SecString $NewPassword ) | Set-Content -Path $pfxpass

# sort all output files in folders
$importantFiles = @(
    $cert
    $chain
    $fullChain
    $key
    $keyplain
    $keypass
    $pfx
    $pfxpass
    if ($basicPFX) {
        $basicPFXpath
    }
)
New-Item -Path '.\Important' -ItemType Directory | Out-Null
foreach ($file in $importantFiles) {
    Move-Item -Path $file -Destination '.\Important'
}

$otherFiles = @( Get-ChildItem -Path '.' -File )
New-Item -Path '.\Other' -ItemType Directory | Out-Null
foreach ($file in $otherFiles) {
    Move-Item -Path $file -Destination '.\Other'
}

# cleanup and success message
Set-Location -Path $PSScriptRoot
"All files are packed and ready in folder:"
'    ' + $workFolder
''

$message = @(
    'The important files:'
    'cert.cer        Your Signed SSL Certificate'
    'chain.cer       Certificate chain bundle containing root CA and intermediate CAs'
    'fullchain.cer   Full chain bundle WITH Signed certificate'
    'key.pem         The Private Key, encrypted by password'
    'keypass.txt     Password for Private Key, in plain text.'
    'keyplain.pem    The Private Key, in plain text'
    'pack.pfx        The full PFX package containing the cert, key, and certificate chain bundle'
    if ($basicPFX) {
        'basic.pfx       A basic PFX package with just the Key, and Cert.'
    }
    'pfxpass.txt     Password for PFX file, in plain text.'
    ''
    'The other files, which might be needed in a pinch:'
    'config.txt      Config used to generate key and CSR with OpenSSL'
    'signrequest.csr The original Certificate Signing Request file. (CSR)'
    'Any other files recieved from your Cert Authority'
    ''
)
$message
explorer.exe "`"$workFolder`""
