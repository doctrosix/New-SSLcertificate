# New-SSLCertificate
# updated 2026-08-10
#
# Requests new x509 certificate from local Enterprise CA server, 
# and outputs certificate in all major file formats:
# PEM, DER, and PFX
#
# Compatible with Powershell 5.1, and Powershell 7.0+
#
# Browse the 'Variables' section, near line 1192, to modify
# values to match your company specs.
# Once variables are set, Simple usage is below:
#   .\New-SSLCertificate.ps1 -FQDN 'server.company.com'
#   .\New-SSLCertificate.ps1 -ConfigFile 'C:\path\to\config.txt'

[CmdletBinding()]
param(
  # Required IF no config file present.
  [string]$FQDN,
  #
  # Required IF no FQDN submitted. Will take an OpenSSL config file if you have one.
  [string]$ConfigFile,
  #
  # Optional. please submit extra FQDNs in quotes separated by commas.
  # accepts arrays.
  # Example:
  #		-ExtraSANs "app.company.com", "db.company.com", "db", "IP:10.24.32.7"
  # Defaults, if param is undefined:
  #       host.company.com.
  #       www.host.company.com.
  [string[]]$ExtraSANs = @(),
  #
  # Optional. Will generate a password if no SecureString is provided
  #[securestring]$NewPassword = (
  #    Read-Host -Prompt "Enter password for private Key and PFX file" -AsSecureString
  #),
  [securestring]$NewPassword,
  #
  # Optional. Will create a new folder based on timestamp
  [string]$WorkFolderName,
  #
  # Optional. For use with Public CA like Digicert, Entrust, etc.
  # if param is unused it defaults to Local-CA submission.
  # Uses Chain file you provided. please edit $caChainFile with your rootchain file name.
  [switch]$forPublicCAsigning
)

begin {
  ################################
  # Functions
  ################################
  function Test-forPowerShell5_1 {
    [CmdletBinding()]
    param ()

    [version]$minPwshVer = '5.0.0.0'
    [version]$maxPwshVer = '5.2.0.0'
    [bool]$isPwsh5_1 = $true

    $isPwsh5_1 = (
      ($PSVersionTable.PSVersion -ge $minPwshVer) -and
      ($PSVersionTable.PSVersion -lt $maxPwshVer)
    )
    return $isPwsh5_1
  }

  # Decrypts SecureStrings to Strings for feeding OpenSSL.exe, and TXT files.
  function Format-SecureString {
    [CmdletBinding()]
    param(
      [Parameter(
        Position = 0,
        Mandatory = $true,
        ValueFromPipeline = $true
      )]
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
      [Parameter(Mandatory = $true)] [bool]$PublicCA
    )

    [string]$san = ''
    [string[]]$allSans = @()
    [string[]]$allButFirst = @()
    $domainsplit = $FQDN.Split('.')
    # $netBIOShostname = $domainsplit[0]

    # Adds basic SANs for deployment flexibility
    #       IF $FQDN equals 'server.company.com'
    #       THEN it adds:
    #           www.server.company.com.
    #           server.
    # The single-word netbios name is disabled for Public CA submission
    [string[]]$basicSANs = @()
    $basicSANs += 'DNS:$FQDN'
    if ( $FQDN -match '^\*' ) {
      # wildcard certs
      # if FQDN is '*.company.com', this outputs 'DNS:company.com'
      $basicSANs += 'DNS:' + ( @( $domainsplit[1..( $domainsplit.Length - 1 )] ) -Join '.' )
    }
    else {
      # Non-wildcard certs
      $basicSANs += ('DNS:www.' + $FQDN.ToLower())
    }

    if ($PublicCA -eq $false) {
      # $basicSANs += 'DNS:' + $netBIOShostname
    }

    # Assemble Subject Alternative Name string
    if ( $ExtraSANs.Length -gt 0 ) {
      [string[]]$formattedSANs = @(
        foreach ( $san in $ExtraSANs ) {
          if ($san.Substring(0, 3) -eq 'IP:') {
            $san.ToUpper()
          }
          elseif ($san.Substring(0, 4) -eq 'DNS:') {
            $san.Substring(0, 4).ToUpper() + $san.Substring(4).ToLower()
          }
          else { 'DNS:' + $san.ToLower() }
        }
      )
      $allSans = $basicSANs + $formattedSANs
      if ($allSans.Length -gt 1) {
        $allButFirst = $allSans[1..($allSans.Length - 1)] | Sort-Object -Unique
        $allSans = @( $allSans[0] ) + $allButFirst
      }
      [string]$altSANs = $allSans -join ', '
    }
    else {
      [string]$altSANs = $basicSANs -join ', '
    }

    # Create config.txt content
    # req_distinguished_name should be ordered big to small
    # Example: Country, State, Locality (City), Org (Company), OU (Department), Common Name (FQDN)
    # C, ST, L, O, OU, CN
    #
    $configContent = @(
      ('FQDN = ' + $FQDN.ToLower())
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
      "ST = NJ"
      "L = West New York"
      'O = $ORGNAME'
      "OU = IT"
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
      [string]$Template,
      [string]$caResp
    )

    [string]$responseName = ''
    [string]$exe = ''
    [string[]]$exeArgs = @()
    [string]$attrib = ''
    [string[]]$certReqOutput = @()
    [string]$certFolderPath = ''
    [string]$responseName = ''
    [string]$responseTXTfilePath = ''
    [bool]$respExists = $false

    # Submit CSR to CA. Then save cert File and CA response.
    $attrib = 'CertificateTemplate:' + $Template
    $exe = Join-Path -Path $env:windir -ChildPath 'System32\certreq.exe'
    $exeArgs = @(
      '-submit',
      '-attrib', $attrib,
      '-config', $WindowsCA,
      $CSRfilePath,
      $CertFilePath
    )
    $certReqOutput = & $exe @exeArgs *>&1

    # Remove Quotes surrounding paths, if needed
    $CSRfilePath = Remove-Quotes $CSRfilePath
    $CertFilePath = Remove-Quotes $CertFilePath

    $noCertIssued = -not (Test-Path -Path $CertFilePath)
    if ($noCertIssued) {
      $certReqOutput | ForEach-Object {
        Write-Host -ForegroundColor Red -Object $_
      }
      Throw "ERROR: Certificate not issued"
    }

    # Process CA response file (certnew.rsp) into readable Text for postgame diagnostics.
    $certFileObj = Get-Item -Path $CertFilePath
    $certFolderPath = $certFileObj.DirectoryName
    $responseName = $certFileObj.BaseName + '.rsp'
    $responseFilePath = Join-Path -Path $certFolderPath -ChildPath $responseName
    $responseTXTfilePath = Join-Path -Path $certFolderPath -ChildPath $caResp
    $exe = Join-Path -Path $env:windir -ChildPath 'System32\certutil.exe'
    $exeArgs = @(
      $responseFilePath
    )
    & $exe @exeArgs > $responseTXTfilePath
    Remove-Item -Path $responseFilePath

    $respExists = Test-Path -Path $responseTXTfilePath
    # returns true if successful. Issued cert file will be found in workfolder.
    return $respExists
  }

  function New-SecureStringPassword {
    [CmdletBinding()]
    param()

    [hashtable]$params = @{
      PasswordLength = 12
      AsSecureString = $true
    }
    [securestring]$secPass = New-PassAlpha @params

    return $secPass
  }

  function New-PassAlpha {
    [CmdletBinding()]
    param (
      [Parameter(Mandatory = $false)]
      [int]$PasswordLength = 32,
      [Parameter(Mandatory = $false)]
      [switch]$IncludeSymbols,
      [Parameter(Mandatory = $false)]
      [switch]$asString,
      [Parameter(Mandatory = $false)]
      [switch]$asSecureString,
      [Parameter(Mandatory = $false)]
      [switch]$asDebugObj
    )

    [int]$passlength = $PasswordLength
    [int]$passlengthMin = 8
    If ($passlength -lt $passlengthMin) {
      [string]$minMsg = (
        "`nMinimum Pasword Length is " +
        $passlengthMin.ToString() +
        ", Generating " +
        $passlengthMin.ToString() +
        " Characters"
      )
      Write-Host $minMsg
      $passlength = $passlengthMin
    }

    # Init password as empty string
    [string]$pass = ''

    ##
    ## Generate one of each char type to satisfy password complexity
    ##

    if ($IncludeSymbols) {
      # add up to 4 symbols
      $symbols = "!@#$%^&-+"
      $symNum = ( Get-Random -Maximum 4 ) + 1
      for ($i = 0; $i -lt $symNum; $i++) {
        [char]$sym = $symbols.ToCharArray() | Get-Random
        $pass += $sym
        $passlength --
      }
    }

    # converts digits to ANSI characters
    # 48-57     = char '0' through '9'
    # 65-90     = char 'A' through 'Z'
    # 97-122    = char 'a' through 'z'
    # 10 numbers + 26 lowercase chars + 26 uppercase chars = 62 possible chars
    [int]$digit = 0
    [char]$sym = 'A'
    # add single number
    $digit = ( Get-Random -Maximum 10 ) + 48
    $sym = $digit.ToChar($null)
    $pass += $sym
    $passlength --

    # add single uppercase letter
    $digit = ( Get-Random -Maximum 26 ) + 65
    $sym = $digit.ToChar($null)
    $pass += $sym
    $passlength --

    # add single lowercase letter
    $digit = ( Get-Random -Maximum 26 ) + 97
    $sym = $digit.ToChar($null)
    $pass += $sym
    $passlength --

    ##
    ## Continue generating characters to satisfy password length
    ##
    for ($i = 0; $i -lt $passlength; $i++) {
      $digit = (Get-Random -Maximum 62) + 48
      # avoids ANSI characters between 0-9 and A-Z
      if ( ( $digit -gt 57 ) -and ( $digit -lt 65 ) ) {
        $digit += 7
      }
      # avoids ANSI characters between A-Z and a-z
      elseif ( ( $digit -gt 90 ) -and ( $digit -lt 97 ) ) {
        $digit += 6
      }

      $sym = $digit.ToChar($null)
      $pass += $sym
    }

    # Shuffles all characters in generated string
    [string]$shufPass = ''
    $shufPass = Start-StringShuffle( $pass )
    $pass = $shufPass

    ########
    # Output
    ########
    [securestring]$secString = $null
    ## for Debugging
    if ($asDebugObj) {
      # a decrypted SecureString should match the String
      $secString = ConvertTo-SecureString -String $pass -AsPlainText -Force
      $decrypted = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR( $secString )
      )
      $dataMatches = $pass -ceq $decrypted
      $debugObj = [PSCustomObject]@{
        string      = $pass
        secString   = $secString
        decrypted   = $decrypted
        dataMatches = $dataMatches
      }
      return $debugObj
    }

    ## Outputs password
    if ($asSecureString) { $asString = $true }

    if ($asString) {
      if ($asSecureString) {
        # Outputs SecureString Object
        $secString = ConvertTo-SecureString -String $pass -AsPlainText -Force
        return $secString
      }
      else {
        # Outputs String Object
        return $pass
      }
    }
    else {
      # Outputs to console, and copies it to clipboard
      [string]$msg = "`nPassword: " + $pass
      Write-Host $msg
      Set-Clipboard $pass
      $msg = "`n" +
      $pass.Length.ToString() + " characters`n" +
      "Password copied to clipboard`n"
      Write-Host $msg
    }

  }


  function Start-StringShuffle {
    [CmdletBinding()]
    param(
      [string]$inputString
    )

    [char[]]$characterArray = $inputString.ToCharArray()
    [char[]]$scrambledStringArray = $characterArray | Get-Random -Count $characterArray.Length
    [string]$outputString = -join $scrambledStringArray
    return $outputString
  }

  function Get-ParentCerts {
    [CmdletBinding()]
    param(
      [System.Security.Cryptography.X509Certificates.X509Certificate2]$cert,
      [int]$fileCounter
    )

    begin {
      [System.Security.Cryptography.X509Certificates.X509Certificate2]$parentCert = $null
      [string[]]$issuerURIs = @()
      [string]$issuer = ''
      [string]$outFile = ''
      [bool]$gotCert = $false
      [bool]$notRoot = $false
      [hashtable]$params = @{}
      [string]$caFilePath = ''
      $aia = $null
    }

    process {
      [version]$ver = '7.0.0'
      [bool]$notPWSH7 = -not ($PSVersionTable.PSVersion -ge $ver)
      if ($notPWSH7) {} else {
        [System.Security.Cryptography.X509Certificates.X509AuthorityInformationAccessExtension]$aia = $null
      }
      if ($fileCounter) {} else { $fileCounter = 0 }

      # Get the Authority Information Access extension,
      # which is at OID 1.3.6.1.5.5.7.1.1
      $aia = (
        $cert.Extensions |
        Where-Object { $_.Oid.Value -eq '1.3.6.1.5.5.7.1.1' }
      )

      if ( $aia ) {
        # get child Issuer URI
        if ($notPWSH7) {
          $issuerURIs = $aia.Format($false) -split ', '
          $issuerURIs = $issuerURIs | Where-Object { $_ -match '^Alternative' }
          $issuerURIs = $issuerURIs | ForEach-Object { $_.Substring(21).Trim() }
        }
        else {
          $issuerURIs = $aia.EnumerateCAIssuersUris()
          $issuerURIs = $issuerURIs | ForEach-Object { $_.Trim() }
        }
      }
      # else {
      #   $outFile = $fileCounter.ToString('00') + '.crt'
      #   $outFile = Join-Path -Path $PWD.Path -ChildPath $outFile
      # }

      foreach ($issuer in $issuerURIs) {
        # try all issuer URIs. break if CA cert is found.

        # [string[]]$uriSplits = $issuer -split '\/'
        # [string]$outFile = $uriSplits[-1]
        # if ($outFile -match '\%\d') {
        #   $outFile = [System.Net.WebUtility]::UrlDecode($outFile)
        # }

        $outFile = $fileCounter.ToString('00') + '.crt'
        $outFile = Join-Path -Path $PWD.Path -ChildPath $outFile
        [string]$issuerURI = ''
        if ($issuer -match '\ \(http') {
          $issuerURI = 'http' + ($issuer -split '\ \(http')[1]
          $issuerURI = $issuerURI.Substring(0, ($issuerURI.Length - 1))
        }
        else { $issuerURI = $issuer }

        # get Issuer CA cert as file
        $params = @{
          Uri         = $issuerURI
          OutFile     = $outFile
          ErrorAction = 'Stop'
        }
        try { Invoke-WebRequest @params }
        catch {
          Write-Host -ForegroundColor Red -Object $issuer
          continue
        }
        $fileCounter ++

        $gotCert = Test-Path -Path $outFile
        if ($gotCert) { break }
      }

      if ($outFile) {
        # Release path string to output stream
        $caFilePath = (Get-Item -Path $outFile).FullName
        $caFilePath
      }

      # ingest ca file into x509 cert object
      if ($caFilePath) { $parentCert = $caFilePath }
      else { $parentCert = $cert.psobject.Copy() }
      # check for self-signed root cert
      $notRoot = $parentCert.Thumbprint -ne $cert.Thumbprint
      if ($notRoot) {
        # recursively find next parent
        Get-ParentCerts -cert $parentCert -fileCounter $fileCounter
      }
    }

    end {}
  }

  function Test-KeyVSfullChain {
    [CmdletBinding()]
    param(
      [string]$keyPath,
      [string]$fullChainPath,
      [string]$opensslEXE
    )

    [string[]]$exeArgs = @()
    [string]$txtOut = ''
    [string]$fullChainModulus = ''
    [string]$keyModulus = ''
    [string]$keyHash = ''
    [string]$fcHash = ''
    [hashtable]$params = @{}

    # get private key modulus
    $exeArgs = @(
      'rsa',
      '-noout',
      '-modulus',
      '-in', $keyFile.FullName
    )
    $txtOut = & $opensslEXE @exeArgs
    $keyModulus = $txtOut.Trim().Split('=')[1]

    # get fullchain modulus
    $exeArgs[0] = 'x509'
    $exeArgs[($exeArgs.IndexOf('-in') + 1)] = $fullChainPath
    $txtOut = & $opensslEXE @exeArgs
    $fullChainModulus = $txtOut.Trim().Split('=')[1]

    # get sha256 has from modulus
    $keyHash = Get-ModulusHash -modulus $keyModulus
    $fcHash = Get-ModulusHash -modulus $fullChainModulus

    # verify key against fullchain
    Write-Host ('        key: ' + $keyHash)
    Write-Host ('  fullchain: ' + $fcHash)
    if ($keyHash -ceq $fcHash) {
      $params = @{
        Object          = 'Key to fullchain verification successful.'
        ForegroundColor = 'Green'
      }
      Write-Host @params
    }
    else {
      Throw 'Key to fullchain verification FAILED'
    }
  }

  function Get-ModulusHash {
    [CmdletBinding()]
    param( [string]$modulus )

    [bool]$badModulus = $true
    [hashtable]$params = @{}
    [string]$hash = ''

    $badModulus = (
      ($modulus -eq '') -or
      ($null -eq $modulus)
    )
    if ($badModulus) { Throw 'Bad modulus string' }

    $ioStream = [System.IO.MemoryStream]::new()
    $writer = [System.IO.StreamWriter]::new($ioStream)
    $writer.Write($modulus)
    $writer.Flush()
    $ioStream.Position = 0
    $params = @{
      InputStream = $ioStream
      Algorithm   = 'SHA256'
    }
    $hash = (
      Get-FileHash @params |
      Select-Object -ExpandProperty 'Hash'
    )
    return $hash
  }

  function Convert-Certs {
    [CmdletBinding()]
    param(
      [string]$CertPath,
      [string]$KeyPath,
      [string]$workDir,
      [string]$secText,
      [securestring]$newPassword,
      [string]$opensslPathStr
    )

    [System.IO.FileInfo]$sourceCert = $null
    [System.IO.FileInfo]$sourceKey = $null
    [string]$stamp = ''
    [string]$tempDir = ''
    [string]$pemDir = ''
    [string]$derDir = ''
    [string]$pfxDir = ''
    [System.IO.FileInfo]$certFile = $null
    [System.IO.FileInfo]$keyFile = $null
    [string]$openssl = 'openssl.exe'
    [string[]]$exeArgs = @()
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$cert = $null
    [string[]]$parents = @()
    [int]$issuerCount = 0
    [string[]]$caFileNames = @()
    [string]$newName = ''
    [string[]]$chainTXT = @()
    [string[]]$fullChainTXT = @()
    [hashtable]$params = @{}
    [object[]]$files = @()
    [string]$passTXT = ''
    [string[]]$notes = @()
    [bool]$noDir = $true
    [string[]]$fullChainFileNames = @()
    [datetime]$certStartDate = '1980-06-06'
    [bool]$needsPass = $true
    [bool]$notPWSH7 = $true
    [string[]]$caNoteLines = @()
    [string]$str = ''
    [int]$count = 0
    [System.IO.DirectoryInfo]$workDirObj = $null
    [string]$exeOutput = ''
    [version]$ver = '1.0.0'

    $ver = '7.0.0'
    $notPWSH7 = -not ($PSVersionTable.PSVersion -ge $ver)

    if ($opensslPathStr) {
      $openssl = $opensslPathStr
    }

    # get cert and key file objects
    try { $sourceCert = Get-Item -Path $CertPath -ErrorAction 'Stop' }
    catch { Throw }
    try { $sourceKey = Get-Item -Path $KeyPath -ErrorAction 'Stop' }
    catch { Throw }

    # create work directory
    if ($workDir) {
      # test workDir param
      $noDir = -not (Test-Path -Path $workDir)
      if ($noDir) {
        Throw 'Work directory does not exist'
      }
      try { $workDirObj = Get-Item -Path $workDir }
      catch { Throw 'WorkDir is not a directory' }
      $workDir = $workDirObj.FullName
    }
    else {
      # create workDir if none submitted
      $stamp = (Get-Date -Format FileDateTime).Substring(0, 13)
      $workDir = Join-Path -Path $PSScriptRoot -ChildPath $stamp
      $workDirObj = New-Item -Path $workDir -ItemType Directory
    }

    # create workDir subfolders
    $tempDir = Join-Path -Path $workDir -ChildPath 'temp'
    $pemDir = Join-Path -Path $workDir -ChildPath 'pem'
    $derDir = Join-Path -Path $workDir -ChildPath 'der'
    $pfxDir = Join-Path -Path $workDir -ChildPath 'pfx'

    New-Item -Path $tempDir -ItemType Directory | Out-Null
    New-Item -Path $pemDir -ItemType Directory | Out-Null
    New-Item -Path $derDir -ItemType Directory | Out-Null
    New-Item -Path $pfxDir -ItemType Directory | Out-Null

    # save current directory for later
    [string]$startDir = $PWD.Path

    # start working from temp folder
    Set-Location -Path $tempDir

    # convert source key to PEM
    $keyFile = New-Item -Path 'key-plain.key' -ItemType 'File'
    [string]$inPath = $sourceKey.FullName
    [string]$outPath = $keyFile.FullName
    if ($notPWSH7) {
      $inPath = Add-Quotes $inPath
      $outPath = Add-Quotes $outPath
    }
    $exeArgs = @(
      'rsa',
      '-outform', 'PEM',
      '-in', $inPath,
      '-out', $outPath
    )
    $exeOutput = & $openssl @exeArgs
    if ($LASTEXITCODE -gt 0) {
      Write-Host -ForegroundColor 'Red' -Object (
        "openssl error:`n" + $openssl + ' ' + ($exeArgs -join ' ') ); exit 1
    }

    # convert source cert file to PEM
    $certFile = New-Item -Path 'cert.crt'
    $inPath = $sourceCert.FullName
    $outPath = $certFile.FullName
    if ($notPWSH7) {
      $inPath = Add-Quotes $inPath
      $outPath = Add-Quotes $outPath
    }
    $exeArgs = @(
      'x509',
      '-outform', 'PEM'
      '-in', $inPath,
      '-out', $outPath
    )
    $exeOutput = & $openssl @exeArgs
    if ($LASTEXITCODE -gt 0) {
      Write-Host -ForegroundColor 'Red' -Object (
        "openssl error:`n" + $openssl + ' ' + ($exeArgs -join ' ') ); exit 1
    }

    # ingest cert file into x509 object
    try { $cert = $certFile.FullName }
    catch {
      Write-Error ($certFile.FullName + ' Not a valid certificate File')
      exit 1
    }

    # get parent certificate authority cert files
    Write-Host 'Requesting all parent certificate authorities...'
    $parents = Get-ParentCerts -cert $cert

    ####
    # convert CA cert files to PEM
    ####
    # flip order so root is numbered 0
    # @(root, intermediate, intermediate)
    $parents = $parents[($parents.Length - 1)..0]

    $issuerCount = 0; [string]$p = ''
    $caFileNames = foreach ($p in $parents) {
      $newName = 'zz-ca' + $issuerCount.ToString('00')
      if ($issuerCount -eq 0) { $newName += '-root.crt' }
      else { $newName += '-int.crt' }

      $caFile = New-Item -Path $newName

      # convert CA cert to PEM
      $inPath = $p
      $outPath = $caFile.FullName
      if ($notPWSH7) {
        $inPath = Add-Quotes $inPath
        $outPath = Add-Quotes $outPath
      }
      $exeArgs = @(
        'x509',
        '-outform', 'PEM'
        '-in', $inPath,
        '-out', $outPath
      )
      $exeOutput = & $openssl @exeArgs
      if ($LASTEXITCODE -gt 0) {
        Write-Host -ForegroundColor 'Red' -Object (
          "openssl error:`n" + $openssl + ' ' + ($exeArgs -join ' ')
        ); exit 1
      }

      $caFile.FullName
      $issuerCount ++
    }
    $issuerCount = 0

    ####
    # create Chain File
    ####
    Write-Host 'Building certificate chains...'
    $chainFile = New-Item -Path 'chain.crt'
    # Flip order again so the chain file order is correct
    # intermediate, intermediate, root
    $caFileNames = $caFileNames[($caFileNames.Length - 1)..0]
    $chainTXT = Get-Content -Path $caFileNames
    $params = @{
      Encoding = 'utf8NoBOM'
      Path     = $chainFile.FullName
    }
    if ($notPWSH7) { $params.Encoding = 'UTF8' }
    $chainTXT | Set-Content @params

    # create fullchain file
    $fullChainFileNames = @(
      $certFile.FullName
      $chainFile.FullName
    )
    $fullChainTXT = Get-Content -Path $fullChainFileNames
    $fullChainFile = New-Item -Path 'fullchain.crt'
    $params = @{
      Encoding = 'utf8NoBOM'
      Path     = $fullChainFile.FullName
    }
    if ($notPWSH7) { $params.Encoding = 'UTF8' }
    $fullChainTXT | Set-Content @params

    # test key vs fullchain
    Write-Host 'Verifying key hash against full chain hash...'
    $params = @{
      keyPath       = $keyFile.FullName
      fullChainPath = $fullChainFile.FullName
      opensslEXE    = $openssl
      ErrorAction   = 'Stop'
    }
    try { Test-KeyVSfullChain @params }
    catch { Throw 'fullchain test failed' }

    # cleanup old parent files
    foreach ($p in $parents) {
      Remove-Item -Path $p
    }

    # create random password files
    $needsPass = (
      (-not $newPassword) -and
      (-not $secTXT)
    )
    $keyPassFile = New-Item -Path 'key-sec-pass.txt'
    if ($needsPass) {
      $passTXT = New-PassAlpha -PasswordLength 8 -asString
    }
    else {
      if ($newPassword) {
        $passTXT = Format-SecureString $newPassword
      }
      elseif ($secTXT) {
        [securestring]$secStringNew = ConvertTo-SecureString -String $secTXT
        $passTXT = Format-SecureString $secStringNew
      }
    }

    $params = @{
      Encoding = 'utf8NoBOM'
      Path     = $keyPassFile.FullName
    }
    if ($notPWSH7) { $params.Encoding = 'UTF8' }
    $passTXT | Set-Content @params
    $passTXT = ''
    Remove-Variable -Name 'passTXT'
    $pfxPassFile = New-Item -Path (
      Join-Path -Path $pfxDir -ChildPath 'pfx-pass.txt'
    )
    Copy-Item -Path $keyPassFile -Destination $pfxPassFile

    # create secure keyFile
    $passArg = 'file:' + $keyPassFile.Name
    $seckeyFile = New-Item -Path 'key-sec.key'

    $inPath = $keyFile.FullName
    $outPath = $seckeyFile.FullName
    if ($notPWSH7) {
      $inPath = Add-Quotes $inPath
      $outPath = Add-Quotes $outPath
    }

    $exeArgs = @(
      'rsa',
      '-des3',
      '-in', $inPath,
      '-passout', $passArg,
      '-out', $outPath
    )
    $exeOutput = & $openssl @exeArgs
    if ($LASTEXITCODE -gt 0) {
      Write-Host -ForegroundColor 'Red' -Object (
        "openssl error:`n" + $openssl + ' ' + ($exeArgs -join ' ') ); exit 1
    }

    # create PEM files
    Write-Host 'Creating PEM files.'
    Set-Location -Path $tempDir
    $files = Get-ChildItem -File
    foreach ( $f in $files ) { $f | Copy-Item -Destination $pemDir }

    # create DER cert files
    Write-Host 'Creating DER files.'
    [object[]]$certFiles = $files | Where-Object Extension -eq '.crt'
    foreach ($f in $certFiles) {
      $destFile = New-Item -Path (
        Join-Path -Path $derDir -ChildPath $f.Name
      )

      $inPath = $f.FullName
      $outPath = $destFile.FullName
      if ($notPWSH7) {
        $inPath = Add-Quotes $inPath
        $outPath = Add-Quotes $outPath
      }
      $exeArgs = @(
        'x509',
        '-outform', 'DER'
        '-in', $inPath,
        '-out', $outPath
      )
      $exeOutput = & $openssl @exeArgs
      if ($LASTEXITCODE -gt 0) {
        Write-Host -ForegroundColor 'Red' -Object (
          "openssl error:`n" + $openssl + ' ' + ($exeArgs -join ' ') ); exit 1
      }
    }

    # create DER key file
    $destFile = New-Item -Path (
      Join-Path -Path $derDir -ChildPath $keyFile.Name
    )

    $inPath = $keyFile.FullName
    $outPath = $destFile.FullName
    if ($notPWSH7) {
      $inPath = Add-Quotes $inPath
      $outPath = Add-Quotes $outPath
    }
    $exeArgs = @(
      'rsa',
      '-outform', 'DER',
      '-in', $inPath,
      '-out', $outPath
    )
    $exeOutput = & $openssl @exeArgs
    if ($LASTEXITCODE -gt 0) {
      Write-Host -ForegroundColor 'Red' -Object (
        "openssl error:`n" + $openssl + ' ' + ($exeArgs -join ' ') ); exit 1
    }

    # create basic PFX
    # cert and key only.
    Write-Host 'Creating PFX files.'
    [string]$pfxPassFilePath = $pfxPassFile.FullName
    if ($notPWSH7) {
      $pfxPassFilePath = Add-Quotes -str $pfxPassFilePath
    }
    $passArg = 'file:' + $pfxPassFilePath
    $destFile = New-Item -Path (
      Join-Path -Path $pfxDir -ChildPath 'pfx-basic.pfx'
    )
    $inKeyPath = $keyFile.FullName
    $inPath = $certFile.FullName
    $outPath = $destFile.FullName
    if ($notPWSH7) {
      $inKeyPath = Add-Quotes $inKeyPath
      $inPath = Add-Quotes $inPath
      $outPath = Add-Quotes $outPath
    }

    $exeArgs = @(
      'pkcs12', '-export',
      "-certpbe", 'NONE'
      "-keypbe", "PBE-SHA1-3DES"
      '-inkey', $inKeyPath,
      "-in", $inPath,
      "-out", $outPath,
      "-passout", $passArg
    )
    $exeOutput = & $openssl @exeArgs
    if ($LASTEXITCODE -gt 0) {
      Write-Host -ForegroundColor 'Red' -Object (
        "openssl error:`n" + $openssl + ' ' + ($exeArgs -join ' ')
      ); exit 1
    }

    $pfxBasicFile = Get-Item $destFile.FullName

    # create fullchain PFX
    # cert, chain, and key.
    $destFile = New-Item -Path (
      Join-Path -Path $pfxDir -ChildPath 'pfx-full.pfx'
    )

    $outPath = $destFile.FullName
    $chainFilePath = $chainFile.FullName
    if ($notPWSH7) {
      $outPath = Add-Quotes $outPath
      $chainFilePath = Add-Quotes $chainFilePath
    }

    $exeArgs[($exeArgs.IndexOf('-out') + 1)] = $outPath
    $exeArgs += @(
      '-certfile', $chainFilePath
    )
    $exeOutput = & $openssl @exeArgs
    if ($LASTEXITCODE -gt 0) {
      Write-Host -ForegroundColor 'Red' -Object (
        "openssl error:`n" + $openssl + ' ' + ($exeArgs -join ' ') ); exit 1
    }

    $pfxFullFile = Get-Item $destFile.FullName

    ###
    # create notes.txt
    ###
    Set-Location -Path $workDir
    $count = $caFileNames.Length
    $caNoteLines = foreach ($path in $caFileNames) {
      $str = Split-Path -Path $path -Leaf
      $isRoot = $str -match '\-root\.crt$'
      if ($isRoot) {
        $str.PadRight(24) + 'Root CA certificate'
      }
      elseif ($caFileNames.Length -gt 2) {
        $str.PadRight(24) + 'Intermediate CA certificate ' + $count.ToString()
      }
      else {
        $str.PadRight(24) + 'Intermediate CA certificate'
      }
      $count --
    }
    $count = 0

    $notes = @(
      '################'
      'File Notes'
      '################'
      ''
      'Look in the der, pem, and pfx folders to get the certificate format you need.'
      ''
      'Within each folder:'
      ($certFile.Name.PadRight(24) + 'The certificate')
      ($chainFile.Name.PadRight(24) + 'All parent CA certificates')
      ($fullChainFile.Name.PadRight(24) + 'The certificate + chain combined' )
      ($seckeyFile.Name.PadRight(24) + 'Secure private key (PEM only)')
      ($keyPassFile.Name.PadRight(24) + 'Password for secure key')
      ($keyFile.Name.PadRight(24) + 'Key in plain text')
    )

    $notes += $caNoteLines
    $notes += @(
      ($pfxBasicFile.Name.PadRight(24) + 'PFX with key and cert only')
      ($pfxFullFile.Name.PadRight(24) + 'PFX with key and full certificate chain')
      ($pfxPassFile.Name.PadRight(24) + 'PFX password')
    )

    $params = @{
      Encoding = 'utf8NoBOM'
      Path     = 'notes.txt'
    }
    if ($notPWSH7) { $params.Encoding = 'UTF8' }
    $notes | Set-Content @params

    # set all file dates to Cert Start date
    $files = Get-ChildItem -Recurse -Force -File
    $certStartDate = $cert.NotBefore
    foreach ($f in $files) {
      $f.CreationTime = $certStartDate
      $f.LastWriteTime = $certStartDate
    }

    $exeOutput | Out-Null
    Write-Host ''
    Write-Host ('All Files saved to: ' + $workDir)
    Write-Host 'Done.'
    Write-Host ''

    # cleanup temp dir
    Remove-Item -Recurse -Force -Path $tempDir

    Set-Location $startDir
    return

  }

  function Add-Quotes {
    [CmdletBinding()]
    param(
      [Parameter(
        Position = 0,
        Mandatory = $true,
        ValueFromPipeline = $true
      )]
      [string]$str
    )

    [bool]$needsQuotes = -not (
      ($str -match '^\"') -and
      ($str -match '\"$')
    )
    if ($needsQuotes) {
      $str = '"' + $str + '"'
    }
    return $str
  }


  function Remove-Quotes {
    [CmdletBinding()]
    param(
      [Parameter(
        Position = 0,
        Mandatory = $true,
        ValueFromPipeline = $true
      )]
      [string]$str
    )

    [bool]$hasQuotes = (
      ($str -match '^\"') -and
      ($str -match '\"$')
    )
    if ($hasQuotes) {
      $str = $str.Substring(1, ($str.Length - 2))
    }

    return $str
  }

  function Format-PathArgs {
    [CmdletBinding()]
    param(
      [string[]]$pathArgs,
      [bool]$isPwsh5
    )

    [string]$s = ''

    if ($isPwsh5) {
      $pathArgs = foreach ($s in $pathArgs) {
        Add-Quotes -str $s
      }
    }

    return $pathArgs
  }

  function Convert-CRLFtoLF {
    [CmdletBinding()]
    param(
      [string]$filePath,
      [string]$destPath
    )

    if ( ! (Test-Path -Path $filePath) ) {
      Throw "File not found: $filePath"
    }

    if ($destPath) {} else {
      $destPath = $filePath
    }

    [version]$ver = '7.0.0'
    [bool]$notPwsh7 = -not ($PSVersionTable.PSVersion -ge $ver)

    [string]$content = Get-Content -Path $filePath -Raw
    $content = $content -replace "`r`n", "`n"
    # Ensure file ends with LF
    if ($content[-1] -ne "`n") { $content += "`n" }

    # convert string to bytes and write to file to preserve LF line endings
    [byte[]]$contentBytes = [System.Text.Encoding]::UTF8.GetBytes($content)
    if ($notPwsh7) {
      [System.IO.File]::WriteAllBytes($destPath, $contentBytes)
    }
    else {
      Set-Content -Value $contentBytes -Path $destPath -AsByteStream
    }

    return
  }

}

process {
  ################################
  # Variables
  ################################
  # Windows CA server: caserver.company.com\CAname
  [string]$companyCAfqdn = 'caserver.lan.company.com'
  [string]$companyCAname = 'SSL-company-Int-CA'
  [string]$companyCA = $companyCAfqdn + '\' + $companyCAname

  # Certificate Template Name
  [string]$certTemplate = 'Web-Server-v03'

  # Your company Name
  [string]$companyNameTXT = 'Company LLC'

  # Define path of OpenSSL installation
  # Uncomment or edit the line to match your installation path
  #
  # OpenSSL 3.x from chocolatey ( choco install openssl.light )
  [string]$openSSL = "C:\Program Files\OpenSSL\bin\openssl.exe"
  #
  # OpenSSL 1.x from GIT
  # [string]$openSSL = "C:\Program Files\Git\usr\bin\openssl.exe"
  #
  # OpenSSL install location on ubuntu 20.x linux
  # [string]$openSSL = '/usr/bin/openssl'

  # Default names for output files
  [string]$configBase = 'config.txt'
  [string]$keyplainBase = 'key-plain.key'
  [string]$csrBase = 'req.csr'
  [string]$certBase = 'cert.crt'
  [string]$caRespBase = 'ca-response.txt'
  ################################

  [bool]$isPwsh5 = $false
  [bool]$configFileExists = $false
  [string[]]$exeArgs = @()
  [string[]]$csrData = @()
  [hashtable]$params = @{}
  [string[]]$paths = @()
  [string]$startDir = ''
  [string[]]$files = @()
  [string[]]$lines = @()

  ################################
  # MAIN
  ################################
  $startDir = $PWD.Path
  Write-Host ''
  # Checks for PowerShell 5.1
  $isPwsh5 = Test-forPowerShell5_1

  [string]$msg = ''

  # check if OpenSSL is installed locally
  $opensslNotInstalled = -not (Test-Path -Path $openSSL)
  if ( $opensslNotInstalled ) {
    $msg = (
      "You need OpenSSL for Windows installed on your machine`n" +
      "You may use one of the following 2 sources:`n" +
      "  git`n" +
      "    Install Git for Windows from https://git-scm.com/`n" +
      "  chocolatey`n" +
      '    Install chocolatey package manager from https://community.chocolatey.org/' + "`n" +
      "       Then run `'choco install openssl.light`'`n"
    )
    Write-Host $msg -ForegroundColor 'Red'
    Throw "OpenSSL not installed"
  }

  # Sets $LocalCACert flag
  if ($forPublicCAsigning) { $LocalCACert = $false }
  else { $LocalCACert = $true }

  # FQDN / Config handling
  if (-not $ConfigFile) { $configFileExists = $false }
  else { $configFileExists = Test-Path -Path $ConfigFile }

  if ($configFileExists) {
    # Do Nothing, $FQDN ignored.
    [string]$cfgFilePath = (Get-Item -Path $ConfigFile).FullName
  }
  else {
    if (-not $FQDN) {
      $FQDN = Read-Host -Prompt "Enter FQDN"
    }
  }

  # Org Handling
  if ($LocalCACert) { $Org = $companyNameTXT }
  else { $Org = Read-Host -Prompt 'Enter Org name' }

  # Generate random password
  if (-not $NewPassword) {
    [securestring]$NewPassword = New-SecureStringPassword
  }

  ####
  # Create and enter Workfolder
  ####

  # Create Workfolder
  if ( -not $workFolderName ) {
    $workFolderName = (Get-Date -Format FileDateTime).Substring(0, 15)
  }
  [string]$workFolder = (
    New-Item -Path $workFolderName -ItemType 'Directory' |
    Select-Object -ExpandProperty 'FullName'
  )

  # prepare Path strings for each workfile.
  [string]$config = Join-Path -Path $workFolder -ChildPath $configBase
  [string]$keyplain = Join-Path -Path $workFolder -ChildPath $keyplainBase
  [string]$csr = Join-Path -Path $workFolder -ChildPath $csrBase
  [string]$cert = Join-Path -Path $workFolder -ChildPath $certBase

  [bool]$workFolderReady = Test-Path -Path $workFolder
  if (-not $workFolderReady) {
    Throw 'Workfolder cannot be created'
  }

  # start working within workFolder
  Set-Location -Path $workFolder

  # If no $ConfigFile is supplied, generate basic config file.
  if ($configFileExists) {
    $content = Get-Content -Path $cfgFilePath
  }
  else {
    [hashtable]$configParams = @{
      FQDN      = $FQDN
      ExtraSANs = $ExtraSANs
      Org       = $Org
      PublicCA  = $false
    }

    if ($forPublicCAsigning) { $configParams.PublicCA = $true }

    $content = New-ConfigContent @configParams
  }
  Set-Content -Value $content -Path $config

  # Create plaintext private Key and CSR files
  $paths = @(
    $config
    $keyplain
    $csr
  )
  $paths = Format-PathArgs -pathArgs $paths -isPwsh5 $isPwsh5
  Write-Host 'Creating keypair and CSR...'
  $exeArgs = @(
    'req',
    '-new',
    '-config', $paths[0],
    '-keyout', $paths[1],
    '-out', $paths[2]
  )
  & $openSSL @exeArgs

  ####
  # Submit CSR and get signed cert.
  ####
  if ($LocalCACert) {
    Write-Host ('Submitting CSR to ' + $companyCA + '...')
  }
  else {
    $msg = (
      "`n" +
      "-Visit your SSL vendor website and submit the CSR.`n" +
      "-Please download PEM, or Base64 format files from the signing CA`n" +
      "-Use the file saved as signrequest.csr or use the Text Below:`n" +
      "`n"
    )
    Write-Host $msg

    # outputs CSR text to screen.
    $csrData = Get-Content -Path $csr
    @($csrData + @("`n")) | ForEach-Object { Write-Host $_ }

    $csrData | Set-Clipboard
    Write-Host "Text Copied to Clipboard`n"

  }

  if ( -not $LocalCACert) {
    $msg = (
      "-Copy the vendor's signed certificate file, and chain file to the work folder:`n" +
      ( '  ' + $workFolder ) + "`n`n"
    )
    Write-Host $msg
  }

  [bool]$localCAcertHasBeenIssued = $false
  $paths = @(
    $csr
    $cert
  )
  $paths = Format-PathArgs -pathArgs $paths -isPwsh5 $isPwsh5
  if ($LocalCACert) {
    $params = @{
      WindowsCA    = $companyCA
      CSRfilePath  = $paths[0]
      CertFilePath = $paths[1]
      Template     = $certTemplate
      caResp       = $caRespBase
    }
    try {
      $localCAcertHasBeenIssued = Send-CSRtoCompanyCA @params
    }
    catch { Throw }
    $SignedCertFile = $cert
  }
  else {
    $msg = "`n-Fill in the blanks below when you're ready`n"
    Write-Host $msg
    $SignedCertFile = Read-Host -Prompt "Enter cert file name"
    $SignedCertFile = ( Get-Item -Path $SignedCertFile -ErrorAction "Stop" ).FullName
    Write-Host ''
  }

  if ($LocalCACert) {
    if ($localCAcertHasBeenIssued) {
      Write-Host "SUCCESS: Certificate Issued`n"
    }
    else {
      Throw 'Cert Rejected by Local CA'
    }
  }

  if ( $SignedCertFile -cne $cert ) {
    Copy-Item -Path $SignedCertFile -Destination $cert
  }

  # Check Cert Chain and convert cert to most file types:
  # DER, PEM, PFX
  $params = @{
    CertPath       = $cert
    KeyPath        = $keyplain
    workDir        = $workFolder
    opensslPathStr = $openSSL
    ErrorAction    = 'Stop'
  }
  if ($NewPassword) {
    $params.Add('newPassword', $NewPassword)
  }
  try { Convert-Certs @params }
  catch { Throw $_ }

  # move certreq files to 'other' folder
  Set-Location $workFolder
  $noDERcert = -not (Test-Path -Path ('.\der\' + $certBase))
  if ($noDERcert) {
    Throw 'Convert-Certs error'
  }
  $otherDir = New-Item -Path 'reqInfo' -ItemType 'Directory'
  $files = @(
    $caRespBase
    $configBase
    $csrBase
  )
  Move-Item -Path $files -Destination $otherDir

  # add Lines to notes.txt
  $lines = @(
    ($configBase.PadRight(24) + 'Cert request config')
    ($csrBase.PadRight(24) + 'CSR sent to CA')
    ($caRespBase.PadRight(24) + 'CA response')
  )
  Add-Content -Value $lines -Path 'notes.txt'

  # cleanup workfolder
  $havePEMcert = Test-Path -Path ('.\pem\' + $certBase)
  if ($havePEMcert) {
    $files = @(
      $certBase
      $keyplainBase
    )
    Remove-Item -Path $files
  }

  # convert all pem files to LF line endings for linux compatibility
  [string[]]$pemFiles = Get-ChildItem -Path '.\pem\*' -File | Select-Object -ExpandProperty 'FullName'
  foreach ($fileName in $pemFiles) {
    Convert-CRLFtoLF -filePath $fileName
  }

  if ($isPwsh5) { $outArg = Add-Quotes -str $workFolder }
  else { $outArg = $workFolder }
  explorer.exe $outArg
  Set-Location -Path $startDir

  return
}
