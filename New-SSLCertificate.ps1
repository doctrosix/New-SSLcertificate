# New-SSLCertificate v2.0

[CmdletBinding()]
param(
    [string]$FQDN = '',
    [string]$Org = '',
    [securestring]$NewPassword = ( Read-Host -Prompt "Enter password for private Key and PFX file" -AsSecureString ),
    [string]$WorkFolderName = ''
)


## FUNCTIONS

# Invoke-Process is similar to Start-Process, except it packs
# console output into a nice hashtable for you.
Function Invoke-Process {
    [CmdletBinding()]
    param(
        [string]$Title,
        [string]$FilePath,
        [Object[]]$ArgumentList
    )
    Try {
        [System.IO.FileInfo]$FilePath = Get-Item -Path $FilePath
    }
    Catch {
        Throw "Invalid Path"
    }

    [string]$FilePath = $FilePath.FullName

    Try {
        $pinfo = New-Object System.Diagnostics.ProcessStartInfo
        $pinfo.FileName = $FilePath
        $pinfo.RedirectStandardError = $true
        $pinfo.RedirectStandardOutput = $true
        $pinfo.UseShellExecute = $false
        $pinfo.Arguments = $ArgumentList

        $p = New-Object -TypeName 'System.Diagnostics.Process'
        $p.StartInfo = $pinfo
        $p.Start() | Out-Null
        $procOutput = $p.StandardOutput.ReadToEnd()
        $procErr = $p.StandardError.ReadToEnd()
        $p.WaitForExit()
        $results = @{
            title    = $Title
            stdout   = $procOutput
            stderr   = $procErr
            exitCode = $p.ExitCode
        }
        return $results
    }
    Catch {
        exit
    }
}

# Decrypts SecureStrings to feed OpenSSL.exe, and TXT files.
function Format-SecureString {
    [CmdletBinding()]
    param(
        [securestring]$SecString
    )

    [string]$plaintext = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR( $SecString )
    )

    return $plaintext
}


# Set Variables
$openSSL = "C:\Program Files\Git\usr\bin\openssl.exe"
$gitNotInstalled = -not (Test-Path -Path $openSSL)
if ( $gitNotInstalled ) {
    Write-Output "Please install Git for Windows at https://git-scm.com/"
    Throw "Git not installed"
}

$config = 'config.txt'
$key = 'key.pem'
$keyplain = 'keyplain.pem'
$keypass = 'keypass.txt'
$csr = 'signrequest.csr'
$cert = 'cert.cer'
$chain = 'chain.cer'
$fullchain = 'fullchain.cer'
$pfx = 'pack.pfx'
$pfxpass = 'pfxpass.txt'

Write-Output "`r`n"
if ($fqdn -eq '') {
    $fqdn = Read-Host -Prompt "Enter FQDN"
}
if ($org -eq '') {
    $org = Read-Host -Prompt "Enter Company Name"
}


# Create and enter Workfolder
if ( $workFolderName -eq '' ) {
    [string]$workFolderName = Get-Date -Format FileDateTimeUniversal
}
[string]$workFolder = ( New-Item -Path $workFolderName -ItemType Directory ).FullName

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

Set-Location -Path $workFolder


# Create config.txt
$content = @(
    "FQDN = $fqdn"
    "ORGNAME = $org"
    'ALTNAMES = DNS:$FQDN, DNS:www.$FQDN'
    ''
    "[ req ]"
    "default_bits = 2048"
    "default_md = sha256"
    "prompt = no"
    "encrypt_key = no"
    "distinguished_name = req_distinguished_name"
    "req_extensions = req_ext"
    "[ req_distinguished_name ]"
    "C = US"
    'O = $ORGNAME'
    'CN = $FQDN'
    "[ req_ext ]"
    'subjectAltName = $ALTNAMES'
)
Set-Content -Value $content -Path $config


# Create Private Key and CSR files
$splat = @{
    Title        = 'OpenSSL'
    FilePath     = $openSSL
    ArgumentList = @(
        'req'
        '-new'
        "-config `"$config`""
        "-keyout `"$keyplain`""
        "-out `"$csr`""
    )
}
Invoke-Process @splat | Out-Null


# Create a password-protected private key file
$splat = @{
    Title        = 'OpenSSL'
    FilePath     = $openSSL
    ArgumentList = @(
        "rsa"
        "-des"
        "-in `"$keyplain`""
        ("-passout pass:" + ( Format-SecureString -SecString $NewPassword ) )
        "-out `"$key`""
    )
}
Invoke-Process @splat | Out-Null
Remove-Variable -Name 'splat'
Set-Content -Value ( Format-SecureString -SecString $NewPassword ) -Path $keypass


# Go and get CSR signed by CA
Write-Output "`r`n-Visit your SSL vendor website and submit the CSR."
Write-Output "-Please download PEM, or Base64 format files"
Write-Output "-Use the file saved as signrequest.csr or use the Text Below:`r`n"
$csrdata = Get-Content -Path $csr      # outputs CSR text to screen.
Write-Output $csrdata
$csrdata | Set-Clipboard
Write-Output "`r`nText Copied to Clipboard"
Write-Output "`r`n-Copy the vendor's signed certificate file, and chain file to the work folder:"
Write-Output ( '    ' + $workFolder )
Write-Output "`r`n-Fill in the blanks below when you're ready`r`n"

$certfile = Read-Host -Prompt "Enter cert file name"
$chainfile = Read-Host -Prompt "Enter chain or bundle file name"

if ( $certfile -cne 'cert.cer' ) {
    Copy-Item -Path ( '.\' + $certfile ) -Destination ( $cert )
}
if ( $chainfile -cne 'chain.cer' ) {
    Copy-Item -Path ( '.\' + $chainfile ) -Destination ( $chain )
}


#Check Cert Chain
Write-Output "`r`nTesting certificate chain..."
$splat = @{
    Title        = 'OpenSSL'
    FilePath     = $openSSL
    ArgumentList = @(
        'verify'
        '-x509_strict'
        "-CAfile `"$chain`""
        "`"$cert`""
    )
}
[string]$chainTest = ( Invoke-Process @splat ).stdout
[string]$stringwork = ($chainTest -split ':')[2]
if ( -not($stringwork -match 'OK') ) {
    Throw "Cert does not link to chain."
}
else {
    Write-Output "PASSED: Certificate chain is valid"
}


# Assemble Full Certificate chain file, fullchain.cer
$fullChainData = Get-Content -Path @(
    $cert
    $chain
)
$fullChainData | Set-Content -Path $fullchain


#Check Key against Fullchain Cert
Write-Output "Testing private key against full certificate chain..."
$splat = @{
    Title        = 'OpenSSL'
    FilePath     = $openSSL
    ArgumentList = @(
        'x509'
        '-noout'
        '-modulus'
        "-in `"$fullChain`""
    )
}
[string]$certModulus = ( Invoke-Process @splat ).stdout

$splat = @{
    Title        = 'OpenSSL'
    FilePath     = $openSSL
    ArgumentList = @(
        'rsa'
        '-noout'
        '-modulus'
        "-in `"$keyplain`""
    )
}
[string]$keyModulus = ( Invoke-Process @splat ).stdout

if ($certModulus -cne $keyModulus) {
    Throw "key does not match certificate"
}
else {
    Write-Output "PASSED: Key matches certificate and chain"
}


#pack the PFX file
$splat = @{
    Title        = 'OpenSSL'
    FilePath     = $openSSL
    ArgumentList = @(
        'pkcs12'
        "-export"
        "-inkey `"$keyplain`""
        "-in `"$cert`""
        "-certfile `"$chain`""
        "-out `"$pfx`""
        ( "-passout pass:" + ( Format-SecureString -SecString $NewPassword ) )
    )
}
Invoke-Process @splat | Out-Null
Remove-Variable -Name 'splat'

( Format-SecureString -SecString $NewPassword ) | Set-Content -Path $pfxpass


# sort all output files in folders
$importantFiles = @(
    $cert
    $key
    $keyplain
    $keypass
    $pfx
    $pfxpass
)
New-Item -Path '.\Important' -ItemType Directory
foreach ($file in $importantFiles) {
    Move-Item -Path $file -Destination '.\Important'
}

$otherFiles = @( Get-ChildItem -Path '.' -File )
New-Item -Path '.\Other' -ItemType Directory
foreach ($file in $otherFiles) {
    Move-Item -Path $file -Destination '.\Other'
}

# cleanup and success message
Set-Location -Path $PSScriptRoot
Write-Output ("`r`nAll files are packed and ready in folder:`r`n" + $workFolder + "`r`n")
Write-Output @'
The important files:
cert.cer        Your Signed SSL Certificate
key.pem         The Private Key, encrypted by password
keypass.txt     Password for Private Key, in plain text.
keyplain.pem    The Private Key, in plain text
pack.pfx        The full PFX package containing the Cert, Key, and Certificate Chain
pfxpass.txt     Password for PFX file, in plain text.

The other files, which might be needed in a pinch:
chain.cer       Certificate chain bundle with root CA and intermediate CAs
config.txt      Config used to generate key and CSR with OpenSSL
fullchain.cer   Full chain bundle WITH Signed certificate
signrequest.csr The original CSR, or 'Certificate Signing Request' file

'@
