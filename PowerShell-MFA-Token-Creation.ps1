###########################################################################
# Generate MFA Secrets and Prepare Link for QR Code Generation
###########################################################################
using namespace System
param($enteredusername, $enteredissuer, $sha1tobase32)
$Script:Base32Charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

$YOURQRGENERATOR = "https://yourdomain.com/MFA/index.html?uri="

<#
	.SYNOPSIS
		Generate an 80-bit key, BASE32 encoded, secret
		and a URL to your preferred site for a QR code.
		The QR code can be used with the Google Authenticator app.

	.EXAMPLE 
		NEW: The command below will generate a full array of OTP settings for a new MFA setup.
		.\PowerShell-MFA-Token-Creation.ps1 -enteredusername TacoBell -enteredissuer "yourdomain.com"
			Name    : TacoBell
	 		Secret  : ATIAO4J24ODGZ6FM
			Base32  : PLSIWF5ZDAGE5A6ABW4YCY2ZDNTJPYWR
	 		SHA1    : 7AE48B17B9180C4E83C00DB98163591B6697E2D1
			KeyUri  : otpauth://totp/TacoBell?secret=PLSIWF5ZDAGE5A6ABW4YCY2ZDNTJPYWR&issuer=yourdomain.com
			Website : https://yourdomain.com/MFA-QR-Generator/index.html?uri=otpauth%3A%2F%2Ftotp%2FTacoBell%3Fsecret%3DPLSIWF5ZDAGE5A6ABW4YCY2ZDNTJPYWR%26issuer%3Dcontoso.org

	.EXAMPLE
 		EXISTING: The command below will generate the outputs for an existing SHA1 secret.
	 	.\PowerShell-MFA-Token-Creation.ps1 -enteredusername TacoBell -enteredissuer "yourdomain.com" -sha1tobase32 7AE48B17B9180C4E83C00DB98163591B6697E2D1
#>

function New-GoogleAuthenticatorSecret{
    [CmdletBinding()]
    Param(
        # Secret length in bytes, must be a multiple of 5 bits for neat BASE32 encoding
        [int]
        [ValidateScript({($_ * 8) % 5 -eq 0})]
        $SecretLength = 10,

        # Use an existing secret code, don't generate one, just wrap it with new text
        [string]
        $UseThisSecretCode = '',
        
        # Launches a web browser to show a QR Code
        [switch]
        $Online = $false,


        # Name is text that will appear under the entry in Google Authenticator app, e.g. a login name
        [string] $Name = 'Example Website:alice@example.com',


        # Issuer is text that will appear over the entry in Google Authenticator app
        [string]
        $Issuer = 'Example Corp 😃'
    )


    # if there's a secret provided then use it, otherwise we need to generate one
    if ($PSBoundParameters.ContainsKey('UseThisSecretCode')) {
    
        $Base32Secret = $UseThisSecretCode
    
    } else {

        # Generate random bytes for the secret
        $byteArrayForSecret = [byte[]]::new($SecretLength)
        [Security.Cryptography.RNGCryptoServiceProvider]::new().GetBytes($byteArrayForSecret, 0, $SecretLength)
    

        # BASE32 encode the bytes
        # 5 bits per character doesn't align with 8-bits per byte input,
        # and needs careful code to take some bits from separate bytes.
        # Because we're in a scripting language let's dodge that work.
        # Instead, convert the bytes to a 10100011 style string:
        $byteArrayAsBinaryString = -join $byteArrayForSecret.ForEach{
            [Convert]::ToString($_, 2).PadLeft(8, '0')
        }


        # then use regex to get groups of 5 bits 
        # -> conver those to integer 
        # -> lookup that as an index into the BASE32 character set 
        # -> result string
        $Base32Secret = [regex]::Replace($byteArrayAsBinaryString, '.{5}', {
            param($Match)
            $Script:Base32Charset[[Convert]::ToInt32($Match.Value, 2)]
        })
    }

	$SHA1Actual = get-hmachash -Secret $Base32Secret -Message $Name -Algorithm SHA1 -Format hex
	$hashByteArray = [byte[]] ($SHA1Actual -replace '..', '0x$&,' -split ',' -ne '')
	$Base32Actual = convertto-base32 -ByteArray $hashByteArray -Raw -Unformatted

    # Generate the URI which needs to go to the Google Authenticator App.
    # URI escape each component so the name and issuer can have punctiation characters.
    $otpUri = "otpauth://totp/{0}?secret={1}&issuer={2}" -f @(
                [Uri]::EscapeDataString($Name),
                $Base32Actual
                [Uri]::EscapeDataString($Issuer)
              )


    # Double-encode because we're going to embed this into a Google Charts URI,
    # and these need to still be encoded in the QR code after Charts webserver has decoded once.
    $encodedUri = [Uri]::EscapeDataString($otpUri)


    # Tidy output, with a link to Google Chart API to make a QR code
    $keyDetails = [PSCustomObject]@{
		Name = $Name
        Secret = $Base32Secret
		Base32 = $Base32Actual
		SHA1 = $SHA1Actual
        KeyUri = $otpUri
        Website = $YOURQRGENERATOR + $encodedUri
    }


    # Online switch references Get-Help -Online and launches a system WebBrowser.
    if ($Online) {
        Start-Process $keyDetails.QrCodeUri
    }


    $keyDetails
}

<#
.Synopsis
  Takes a Google Authenticator secret like 5WYYADYB5DK2BIOV
  and generates the PIN code for it
.Example
  PS C:\>Get-GoogleAuthenticatorPin -Secret 5WYYADYB5DK2BIOV
  372 251
#>
function Get-GoogleAuthenticatorPin
{
    [CmdletBinding()]
    Param
    (
        # BASE32 encoded Secret e.g. 5WYYADYB5DK2BIOV
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string]
        $Secret,

        # OTP time window in seconds
        $TimeWindow = 30
    )


    # Convert the secret from BASE32 to a byte array
    # via a BigInteger so we can use its bit-shifting support,
    # instead of having to handle byte boundaries in code.
    $bigInteger = [Numerics.BigInteger]::Zero
    foreach ($char in ($secret.ToUpper() -replace '[^A-Z2-7]').GetEnumerator()) {
        $bigInteger = ($bigInteger -shl 5) -bor ($Script:Base32Charset.IndexOf($char))
    }

    [byte[]]$secretAsBytes = $bigInteger.ToByteArray()
    
    
    # BigInteger sometimes adds a 0 byte to the end,
    # if the positive number could be mistaken as a two's complement negative number.
    # If it happens, we need to remove it.
    if ($secretAsBytes[-1] -eq 0) {
        $secretAsBytes = $secretAsBytes[0..($secretAsBytes.Count - 2)]
    }
    
    Write-Output "--- Format 1"
    write-Output (Format-Hex -InputObject $secretAsBytes)
    Write-Output "---"


    # BigInteger stores bytes in Little-Endian order, 
    # but we need them in Big-Endian order.
    [array]::Reverse($secretAsBytes)
    

    # Unix epoch time in UTC and divide by the window time,
    # so the PIN won't change for that many seconds
    $epochTime = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    
    # Convert the time to a big-endian byte array
    $timeBytes = [BitConverter]::GetBytes([int64][math]::Floor($epochTime / $TimeWindow))
    if ([BitConverter]::IsLittleEndian) { 
        [array]::Reverse($timeBytes) 
    }

    # Do the HMAC calculation with the default SHA1
    # Google Authenticator app does support other hash algorithms, this code doesn't
    $hmacGen = [Security.Cryptography.HMACSHA1]::new($secretAsBytes)
    $hash = $hmacGen.ComputeHash($timeBytes)
    
    Write-Output "---"
    write-Output (Format-Hex -InputObject $hmacGen)
    Write-Output "---"
    Write-Output "---"
    write-Output (Format-Hex -InputObject $hash)
    Write-Output "---"

    # The hash value is SHA1 size but we want a 6 digit PIN
    # the TOTP protocol has a calculation to do that
    #
    # Google Authenticator app may support other PIN lengths, this code doesn't
    
    # take half the last byte
    $offset = $hash[$hash.Length-1] -band 0xF

    # use it as an index into the hash bytes and take 4 bytes from there, #
    # big-endian needed
    $fourBytes = $hash[$offset..($offset+3)]
    if ([BitConverter]::IsLittleEndian) {
        [array]::Reverse($fourBytes)
    }

    # Remove the most significant bit
    $num = [BitConverter]::ToInt32($fourBytes, 0) -band 0x7FFFFFFF
    
    # remainder of dividing by 1M
    # pad to 6 digits with leading zero(s)
    # and put a space for nice readability
    $PIN = ($num % 1000000).ToString().PadLeft(6, '0').Insert(3, ' ')

    [PSCustomObject]@{
        'PIN Code' = $PIN
        'Seconds Remaining' = ($TimeWindow - ($epochTime % $TimeWindow))
    }
}

function Get-HMACHash {
    ## get-hmachash -Secret SecretKeyHere -Message UsernameHere -Algorithm SHA1 -Format hex
    [CmdletBinding()]
    param (
        # Message to geneate a HMAC hash for
        [Parameter(Mandatory = $true,
            Position = 0,
            ParameterSetName = "Default",
            ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Message,
        # Secret Key
        [Parameter(Mandatory = $true,
            Position = 1,
            ParameterSetName = "Default",
            ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [Alias("Key")]
        [String]
        $Secret,
        # Algorithm
        [Parameter(Mandatory = $false,
            Position = 2,
            ParameterSetName = "Default",
            ValueFromPipelineByPropertyName = $true)]
        [ValidateSet("MD5", "SHA1", "SHA256", "SHA384", "SHA512")]
        [Alias("alg")]
        [String]
        $Algorithm = "SHA256",
        # Output Format
        [Parameter(Mandatory = $false,
            Position = 2,
            ParameterSetName = "Default",
            ValueFromPipelineByPropertyName = $true)]
        [ValidateSet("Base64", "HEX", "hexlower")]
        [String]
        $Format = "Base64"
    )


    $hmac = switch ($Algorithm) {
        "MD5" { New-Object System.Security.Cryptography.HMACMD5; break }
        "SHA1" { New-Object System.Security.Cryptography.HMACSHA1; break }
        "SHA256" { New-Object System.Security.Cryptography.HMACSHA256; break }
        "SHA384" { New-Object System.Security.Cryptography.HMACSHA384; break }
        "SHA512" { New-Object System.Security.Cryptography.HMACSHA512; break }
    }

    $hmac.key = [Text.Encoding]::UTF8.GetBytes($secret)
    $signature = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($message))

    $signature = switch ($Format) {
        "HEX" { ($signature | ForEach-Object ToString X2 ) -join '' }
        "hexlower" { ($signature | ForEach-Object ToString x2 ) -join '' }
        Default { [Convert]::ToBase64String($signature) }
    }
   
    return ($signature)
}

Function ConvertTo-Base32() {
    <#
    .SYNOPSIS
        A PowerShell function to convert arbitrary data into a Base32 encoded string.
 
    .DESCRIPTION
        Takes a string, byte array or file object as input and returns a Base32 encoded string
        or location of the Base32 result output file object. The default input and output type
        if positional parameters are used is [System.String].
 
    .PARAMETER Bytes
        [System.Byte[]] object containing a byte array to be encoded as Base32 string. Accepts
        pipeline input.
 
    .PARAMETER String
        [System.String] object containing plain text to be encoded as Base32 string. Accepts
        pipeline input.
 
    .PARAMETER InFile
        [System.IO.Fileinfo] object containing the details of a file on disk to be converted to
        Base32 string and output as a new file; output files are written as UTF-8 no BOM.
        Accepts pipeline input.
 
    .PARAMETER OutFile
        Optional [System.IO.Fileinfo] object containing the details of the new file to write to
        disk containing Base32 encoded data from the input file. Can be used with any input mode
        (Bytes, String, or InFile).
 
    .PARAMETER Unormatted
        By default the function adds line breaks to output string every 64 characters and block
        style header / footer (-----BEGIN BASE32 ENCODED DATA-----/-----END BASE32 ENCODED
        DATA-----); this parameter suppresses formatting and returns the Base32 string result as
        a single, unbroken string object with no header or footer.
 
    .PARAMETER Base32Hex
        Use the alternative charset described in RFC4648 for "Base32 Hex"
        (0123456789ABCDEFGHIJKLMNOPQRSTUV) instead of the typical Base32 charset
        (ABCDEFGHIJKLMNOPQRSTUVWXYZ234567).
 
    .PARAMETER AutoSave
        [System.String] containing a new file extension to use to automatically generate files.
        When paired with -InFile, automatically create an output filename of in the form of the
        original file name plus the suffix specified after the parameter, for example -AutoSave
        "B32" would create the OutFile name <InFile>.b32. Useful if piping the output of
        Get-ChildItem to the function to convert files as a bulk operation. Cannot be used with
        input methods other than -InFile.
 
    .PARAMETER Raw
        Optional switch parameter that when present will produce raw string output instead of a
        PSObject. This parameter limits the functionality of the pipeline but is convenient for
        simple encoding operations.
 
    .INPUTS
        Any single object or collection of strings, bytes, or files (such as those from
        Get-ChildItem) can be piped to the function for processing into Base32 encoded data.
 
    .OUTPUTS
        The output is always an ASCII string; if any input method is used with -OutFile or
        -InFile is used with -AutoSave, the output is a [System.IO.FileInfo] object containing
        details of a UTF8 no BOM text file with the Base32 encoded data as contents. Unless
        -Unformatted is specified, the console or file string data is formatted with block
        headers (-----BEGIN BASE32 ENCODED DATA-----/-----END BASE32 ENCODED DATA-----) and line
        breaks are added every 64 character. If -Unformatted is present, the output is a
        [System.String] with no line breaks or header / footer. If outputting to the console,
        the string is returned within a PSObject with a single member named Base32EncodedData as
        [System.String]; if -Raw is specified, the [System.String] is not wrapped in a PSObject
        and returned directly. This means that output using -Raw cannot easily use the pipeline,
        but makes it a useful option for quick encoding operations. The -Verbose parameter will
        return the function's total execution time.
 
    .EXAMPLE
        Convert a string directly into Base32:
            ConvertTo-Base32 "This is a plaintext string"
 
    .EXAMPLE
        Pipe an object (string or array of strings, byte array or array of byte arrays, file
        info or array of file info objects) to the function for encoding as Base32:
            $MyObject | ConvertTo-Base32
    .EXAMPLE
        Convert a byte array to Base32 and return the output with block formatting and not
        wrapped in a PSObject (as a raw [System.String]):
            ConvertTo-Base32 -ByteArray $Bytes -Raw
 
    .EXAMPLE
        Load the contents of a file as byte array and convert directly into Base32-Hex:
            ConvertTo-Base32 -Base32Hex -ByteArray ([System.IO.File]::ReadAllBytes('C:\File.txt'))
 
    .EXAMPLE
        Pipe the results of a directory listing from Get-ChildItem and generate a new Base32
        encoded file with block formatting for each input file:
            Get-ChildItem C:\Text\*.txt | ConvertTo-Base32 -AutoSave "B32"
 
    .EXAMPLE
        Use file based input to Base32 encode an input file and output the results as new file
        C:\Text\base32.txt with no line breaks or header / footer:
            ConvertTo-Base32 -File C:\Text\file.txt -OutFile C:\Text\base32.txt -Unformatted
 
    .NOTES
        More information on the Base16, Base32, and Base64 Data Encoding standard can be found
        on the IETF web site: https://tools.ietf.org/html/rfc4648
    #>
    [CmdletBinding(
        SupportsShouldProcess=$True,
        ConfirmImpact="High",
        DefaultParameterSetName="StringInput"
    )]
    [OutputType([System.Management.Automation.PSObject])]
    Param(
        [Parameter(
            ParameterSetName="ByteInput",
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True,
            Mandatory=$True,
            Position=0,
            HelpMessage='Byte array to Base32 encode.'
        )]
        [ValidateNotNullOrEmpty()]
        [Alias('ByteArray','Data')]
        [System.Byte[]]$Bytes,
        [Parameter(
            ParameterSetName="StringInput",
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True,
            Mandatory=$True,
            Position=0,
            HelpMessage='String to Base32 encode.'
        )]
        [ValidateNotNullOrEmpty()]
        [Alias('Plaintext','Text')]
        [System.String]$String,
        [Parameter(
            ParameterSetName="FileInput",
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True,
            Mandatory=$True,Position=0,
            HelpMessage='File to Base32 encode.'
        )]
        [ValidateNotNullOrEmpty()]
        [Alias('Filename','FullName','File')]
        [ValidateScript({
            If (-Not($_ | Test-Path -PathType Leaf)) {
                throw ("Invalid input file name specified.")
            }Else{
                $True
            }
        })]
        [ValidateScript({
            Try {
                $_.Open([System.IO.FileMode]::Open,[System.IO.FileAccess]::Read,[System.IO.FileShare]::None).Close()
                $True
            }
            Catch {
                throw ("Input file is locked for reading or could not obtain read access.")
            }
        })]
        [System.IO.Fileinfo]$InFile,
        [Parameter(
            ParameterSetName="StringInput",
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True,
            Mandatory=$False,
            Position=1,
            HelpMessage='Output result to specified file as UTF8-NoBOM text instead of console.'
        )]
        [Parameter(
            ParameterSetName="ByteInput"
         )]
        [Parameter(
            ParameterSetName="FileInput"
         )]
        [ValidateNotNullOrEmpty()]
        [System.IO.Fileinfo]$OutFile,
        [Parameter(
            ParameterSetName="ByteInput",
            ValueFromPipeline=$False,
            ValueFromPipelineByPropertyName=$False,
            Mandatory=$False,
            HelpMessage='Do not format output string using header/footer and line breaks.'
        )]
        [Parameter(
            ParameterSetName="StringInput"
         )]
        [Parameter(
            ParameterSetName="FileInput"
         )]
        [ValidateNotNullOrEmpty()]
        [Switch]$Unformatted,
        [Parameter(
            ParameterSetName="ByteInput",
            ValueFromPipeline=$False,
            ValueFromPipelineByPropertyName=$False,
            Mandatory=$False,
            HelpMessage='Use extended Base32 Hex charset instead of standard Base32 charset.'
        )]
        [Parameter(
            ParameterSetName="StringInput"
         )]
        [Parameter(
            ParameterSetName="FileInput"
         )]
        [ValidateNotNullOrEmpty()]
        [Switch]$Base32Hex,
        [Parameter(
            ParameterSetName="FileInput",
            ValueFromPipeline=$False,
            ValueFromPipelineByPropertyName=$False,
            Mandatory=$False,
            HelpMessage='When in file input mode, automatically select output file name using the specified suffix as the file extension; not valid with any other input mode (String or Bytes).'
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            If (-Not(($_.IndexOfAny([System.IO.Path]::GetInvalidFileNameChars()) -eq -1))) {
                throw ("AutoSave suffix contains illegal characters.")
            } Else {
                $True
            }
        })]
        [System.String]$AutoSave,
        [Parameter(
            ParameterSetName="ByteInput",
            ValueFromPipeline=$False,
            ValueFromPipelineByPropertyName=$False,
            Mandatory=$False,
            HelpMessage='When returning a string instead of a file, return a raw string instead of PSObject; applies to both console and file output modes.'
        )]
        [Parameter(
            ParameterSetName="StringInput"
         )]
        [Parameter(
            ParameterSetName="FileInput"
         )]
        [ValidateNotNullOrEmpty()]
        [Switch]$Raw
    )
    BEGIN {
        If ($Base32Hex) {
            [System.String]$B32CHARSET = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
            [System.String]$B32Name = "Base32-Hex"
        } Else {
            [System.String]$B32CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
            [System.String]$B32Name = "Base32"
        }
        [System.String]$B32Header = "-----BEGIN $($B32Name.ToUpper()) ENCODED DATA-----"
        [System.String]$B32Footer = "-----END $($B32Name.ToUpper()) ENCODED DATA-----"
    }
    PROCESS {
        If ($PSBoundParameters.ContainsKey('InFile') -and $PSBoundParameters.ContainsKey('AutoSave')) {
            $OutFile = ($InFile.FullName.ToString()) + ".$($AutoSave)"
        }
        If ($OutFile) {
            If ((Test-Path $OutFile -PathType Leaf) -and ($PSCmdlet.ShouldProcess($OutFile,'Overwrite'))) {
                Remove-Item $OutFile -Confirm:$False
            }
            If (Test-Path $OutFile -PathType Leaf) {
                Write-Error "Could not overwrite existing output file '$($Outfile)'" -ErrorAction Stop
            }
            $Null = New-Item -Path $OutFile -ItemType File
            If ($Raw) {
                Write-Warning "File output mode specified; Parameter '-Raw' will be ignored."
            }
        }
        Switch ($PSCmdlet.ParameterSetName) {
            "ByteInput" {
                [System.IO.Stream]$InputStream = New-Object -TypeName System.IO.MemoryStream(,$Bytes)
                Break
            }
            "StringInput" {
                [System.IO.Stream]$InputStream = New-Object -TypeName System.IO.MemoryStream(,[System.Text.Encoding]::ASCII.GetBytes($String))
                Break
            }
            "FileInput" {
                [System.IO.Stream]$InputStream  = [System.IO.File]::Open($InFile.FullName,[System.IO.FileMode]::Open,[System.IO.FileAccess]::Read,[System.IO.FileShare]::ReadWrite)
                Break
            }
        }
        [System.Object]$Timer = [System.Diagnostics.Stopwatch]::StartNew()
        [System.Object]$BinaryReader = New-Object -TypeName System.IO.BinaryReader($InputStream)
        [System.Object]$Base32Output = New-Object -TypeName System.Text.StringBuilder
        If (-Not $Unformatted) {
            [void]$Base32Output.Append("$($B32Header)`r`n")
        }
        Try {
            While ([System.Byte[]]$BytesRead = $BinaryReader.ReadBytes(5)) {
                [System.Boolean]$AtEnd = ($BinaryReader.BaseStream.Length -eq $BinaryReader.BaseStream.Position)
                [System.UInt16]$ByteLength = $BytesRead.Length
                If ($ByteLength -lt 5) {
                    [System.Byte[]]$WorkingBytes = ,0x00 * 5
                    [System.Buffer]::BlockCopy($BytesRead,0,$WorkingBytes,0,$ByteLength)
                    [System.Array]::Resize([ref]$BytesRead,5)
                    [System.Buffer]::BlockCopy($WorkingBytes,0,$BytesRead,0,5)
                }
                [System.Char[]]$B32Chars = ,0x00 * 8
                [System.Char[]]$B32Chunk = ,"=" * 8
                $B32Chars[0] = ($B32CHARSET[($BytesRead[0] -band 0xF8) -shr 3])
                $B32Chars[1] = ($B32CHARSET[(($BytesRead[0] -band 0x07) -shl 2) -bor (($BytesRead[1] -band 0xC0) -shr 6)])
                $B32Chars[2] = ($B32CHARSET[($BytesRead[1] -band 0x3E) -shr 1])
                $B32Chars[3] = ($B32CHARSET[(($BytesRead[1] -band 0x01) -shl 4) -bor (($BytesRead[2] -band 0xF0) -shr 4)])
                $B32Chars[4] = ($B32CHARSET[(($BytesRead[2] -band 0x0F) -shl 1) -bor (($BytesRead[3] -band 0x80) -shr 7)])
                $B32Chars[5] = ($B32CHARSET[($BytesRead[3] -band 0x7C) -shr 2])
                $B32Chars[6] = ($B32CHARSET[(($BytesRead[3] -band 0x03) -shl 3) -bor (($BytesRead[4] -band 0xE0) -shr 5)])
                $B32Chars[7] = ($B32CHARSET[$BytesRead[4] -band 0x1F])
                [System.Array]::Copy($B32Chars,$B32Chunk,([Math]::Ceiling(($ByteLength / 5) * 8)))
                If ($BinaryReader.BaseStream.Position % 8 -eq 0 -and -Not $Unformatted -and -not $AtEnd) {
                    [void]$Base32Output.Append($B32Chunk)
                    [void]$Base32Output.Append("`r`n")
                } Else {
                    [void]$Base32Output.Append($B32Chunk)
                }
            }
            If (-Not $Unformatted) {
                [void]$Base32Output.Append("`r`n$($B32Footer)")
            }
            [System.String]$Base32Result = $Base32Output.ToString()
            $Base32ResultObject = New-Object -TypeName PSObject
            If ($OutFile) {
                [System.IO.File]::WriteAllLines($OutFile.FullName,$Base32Result,(New-Object -TypeName System.Text.UTF8Encoding $False))
                $Base32ResultObject = $OutFile
            } Else {
                If ($Raw) {
                    $Base32ResultObject = $Base32Result
                } Else {
                    Add-Member -InputObject $Base32ResultObject -MemberType 'NoteProperty' -Name 'Base32EncodedData' -Value $Base32Result
                }
            }
            Return ($Base32ResultObject)
        }
        Catch {
            Write-Error "Exception: $($_.Exception.Message)"
            Break
        }
        Finally {
            $BinaryReader.Close()
            $BinaryReader.Dispose()
            $InputStream.Close()
            $InputStream.Dispose()
            $Timer.Stop()
            [System.String]$TimeLapse = "Base32 encode completed after $($Timer.Elapsed.Hours) hours, $($Timer.Elapsed.Minutes) minutes, $($Timer.Elapsed.Seconds) seconds, $($Timer.Elapsed.Milliseconds) milliseconds"
            Write-Verbose $TimeLapse
        }
    }
}


if ($sha1tobase32 -eq $null) {
    New-GoogleAuthenticatorSecret -Name $enteredusername -Issuer $enteredissuer |FL
}
else {
	$hashByteArray = [byte[]] ($sha1tobase32 -replace '..', '0x$&,' -split ',' -ne '')
	$Base32Actual = convertto-base32 -ByteArray $hashByteArray -Raw -Unformatted

    # Generate the URI which needs to go to the Google Authenticator App.
    # URI escape each component so the name and issuer can have punctiation characters.
    $otpUri = "otpauth://totp/{0}?secret={1}&issuer={2}" -f @(
                [Uri]::EscapeDataString($enteredusername),
                [Uri]::EscapeDataString($Base32Actual),
                [Uri]::EscapeDataString($enteredissuer)
              )
    # Double-encode because we're going to embed this into a Google Charts URI,
    # and these need to still be encoded in the QR code after Charts webserver has decoded once.
    $encodedUri = [Uri]::EscapeDataString($otpUri)


    # Tidy output
    $keyDetails = [PSCustomObject]@{
		Name = $enteredusername
        Secret = $Base32Secret
		Base32 = $Base32Actual
		SHA1 = $SHA1Actual
        KeyUri = $otpUri
        Website = $YOURQRGENERATOR + $encodedUri
    }


    # Online switch references Get-Help -Online and launches a system WebBrowser.
    if ($Online) {
        Start-Process $keyDetails.QrCodeUri
    }


    $keyDetails
}
