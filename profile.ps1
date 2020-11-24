# custom globals
$global:CLOUDTENANT=$null

function checkLastCommand
{
    try
    {
        $lastCommand="$((h)[-1].CommandLine)"

        if ($lastCommand.ToLower().StartsWith("connect-msolservice"))
        {
            $previousTenant=$global:CLOUDTENANT
		    $global:CLOUDTENANT = (Get-MsolDomain -ErrorAction SilentlyContinue | where {$_.Name -match "^([a-z]|[0-9])+\.onmicrosoft\.com$"} | select -ExpandProperty Name).Replace(".onmicrosoft.com","")
		    if ($previousTenant -and $previousTenant -ne $global:CLOUDTENANT)
		    {
			    Write-Warning "Tenant change! Previous tenant was: $previousTenant, it is possible that you are connected to multiple tenants now!"
		    }
        }
        if ($lastCommand.ToLower().StartsWith("connect-azuread"))
        {
            $previousTenant=$global:CLOUDTENANT
		    $global:CLOUDTENANT = (Get-AzureADDomain -ErrorAction SilentlyContinue | where {$_.Name -match "^([a-z]|[0-9])+\.onmicrosoft\.com$"} | select -ExpandProperty Name).Replace(".onmicrosoft.com","")
		    if ($previousTenant -and $previousTenant -ne $global:CLOUDTENANT)
		    {
			    Write-Warning "Tenant change! Previous tenant was: $previousTenant, it is possible that you are connected to multiple tenants now!"
		    }
        }
        if ($lastCommand.ToLower().StartsWith("connect-aadrmservice")-or($lastCommand.ToLower().StartsWith("connect-aipservice")))
        {
            $previousTenant=$global:CLOUDTENANT
		    $global:CLOUDTENANT = (Get-AadrmKeys |?{$_.Status -eq "Active"}).FriendlyName
		    if ($previousTenant -and $previousTenant -ne $global:CLOUDTENANT)
		    {
			    Write-Warning "Tenant change! Previous tenant was: $previousTenant, it is possible that you are connected to multiple tenants now!"
		    }
        }
        if ($lastCommand.ToLower().StartsWith("loadexo"))
        {
            $previousTenant=$global:CLOUDTENANT
		    $global:CLOUDTENANT = (Get-OrganizationConfig -ErrorAction SilentlyContinue | select -ExpandProperty DisplayName)
		    if ($previousTenant -and $previousTenant -ne $global:CLOUDTENANT)
		    {
			    Write-Warning "Tenant change! Previous tenant was: $previousTenant, it is possible that you are connected to multiple tenants now!"
		    }
        }

# 
# Since W1809 we have built-in history in %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\
#
#	    if (($HistoryFilePath) -and (-not ($host.Name -match "ISE"))) 
#	    {
#		    try
#		    {
#			    Get-History | Export-Clixml $HistoryFilePath
#		    }catch
#		    {
#			    Write-Warning "Error writing the history $($_.Exception)"
#		    }
#	    }
#
    }catch
    {
        # just ignore that we were not able to search through history
    }
}

function Prompt 
{
    # check last command
    checkLastCommand
    # Print the current time:
    Write-Host ("[") -nonewline -foregroundcolor DarkGray
    Write-Host (Get-Date -format "yyyy-MM-dd HH:mm:ss") -nonewline -foregroundcolor Gray
    Write-Host ("][") -nonewline -foregroundcolor DarkGray
    If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator"))
    {
        Write-Host "$(whoami)@" -nonewline -foregroundcolor Gray
    }else
    {
        Write-Host "$($(whoami).ToString().ToUpper())" -nonewline -foregroundcolor Cyan
        Write-Host "@" -nonewline -foregroundcolor Gray
    }
    Write-Host "$(hostname)" -nonewline -foregroundcolor Magenta
    Write-Host ("]") -foregroundcolor DarkGray -NoNewline
    if ($global:CLOUDTENANT)
    {
        $host.ui.RawUI.WindowTitle = "PS @MSOL:$($global:CLOUDTENANT)"
        Write-Host "[@$($global:CLOUDTENANT)]" -foregroundcolor Cyan -NoNewline
    }
    
    Write-Host ("")
    return "PS $($executionContext.SessionState.Path.CurrentLocation)$('>' * ($nestedPromptLevel + 1)) "
}

function Uptime
{
    Get-WmiObject win32_operatingsystem | select csname, @{LABEL='LastBootUpTime'; EXPRESSION={$_.ConvertToDateTime($_.lastbootuptime)}}, @{LABEL='Uptime'; EXPRESSION={([System.DateTime]::Now-$_.ConvertToDateTime($_.lastbootuptime))}}
}

function Format-Xml 
{
    <#
   .SYNOPSIS
    Format the incoming object as the text of an XML document.
   #>
    param(
    ## Text of an XML document.
    [Parameter(ValueFromPipeline = $true)]
    [string[]]$Text
    )
    
    begin {
        $data = New-Object System.Collections.ArrayList
    }
    process {
        [void] $data.Add($Text -join "`n")
    }
    end {
        $doc=New-Object System.Xml.XmlDataDocument
        $doc.LoadXml($data -join "`n")
        $sw=New-Object System.Io.Stringwriter
        $writer=New-Object System.Xml.XmlTextWriter($sw)
        $writer.Formatting = [System.Xml.Formatting]::Indented
        $doc.WriteContentTo($writer)
        $sw.ToString()
    }
}

function Format-JWT
{
    <#
   .SYNOPSIS
    Format the incoming object as the text of an XML document.
   #>
    param(
    ## Text of an XML document.
    [Parameter(ValueFromPipeline = $true)][string[]]$Text,
    [Parameter()][switch]$AsJson
    )
    $parts=$Text.Split(".")
    if ($parts.Count -ne 3)
    {
        throw "Inccorect JWT, expacting three b64 strings seperated by '.'"
    }

    # pad parts
    for($i=0;$i -lt 2;$i++)
    {
        $len=$parts[$i].Length
        if ($len % 4 -eq 2) {$parts[$i]=$parts[$i]+"=="}
        if ($len % 4 -eq 3) {$parts[$i]=$parts[$i]+"="}
    }

    $result= New-Object psobject
    try
    {
        $toDecode=$parts[0]
        $header=$toDecode | Base64-To-String | ConvertFrom-Json 
        $result | Add-Member -MemberType NoteProperty Header -Value $header -Force
    }catch
    {
        throw "Error decoding JWT header: $($_.exception.message)"
    }
    try
    {
        $toDecode=$parts[1]
        $toDecodeLenMod=$toDecode.Length % 4
        $payload=$toDecode | Base64-To-String | ConvertFrom-Json 
        $result | Add-Member -MemberType NoteProperty Payload -Value $payload -Force
    }catch
    {
        throw "Error decoding JWT payload: $($_.exception.message)"
    }

    if ($AsJson.IsPresent)
    {
        return $result | ConvertTo-Json
    }
    $result
}

function Base64-To-String
{
    param(
    ## Text of an XML document.
    [Parameter(ValueFromPipeline = $true)]
    [string[]]$Text
    )
    [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Text));
}

function Base64-To-UnicodeString
{
    param(
    ## Text of an XML document.
    [Parameter(ValueFromPipeline = $true)]
    [string[]]$Text
    )
    [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($Text));
}

function Base64-To-HexString
{
    param(
    ## Text of an XML document.
    [Parameter(ValueFromPipeline = $true)]
    [string[]]$Text
    )
    ByteArray-To-HexString([System.Convert]::FromBase64String($Text));
}

function ByteArray-To-HexString
{
    param(
    ## Text of an XML document.
    [Parameter(ValueFromPipeline = $true)]
    [byte[]]$byteArray
    )
    ([System.BitConverter]::ToString($byteArray)).Replace("-"," ").ToLower()
}

function HexString-To-ByteArray
{
    param(
    ## Text of an XML document.
    [Parameter(ValueFromPipeline = $true)]
    [string]$hexString
    )
    try
    {
        $bytes=$hexString -split "\s+";
        [byte[]] $returnValue=@();
        foreach($byte in $bytes)
        {
            $returnValue+=[byte]"0x$byte"
        }
        $returnValue
    }catch
    {
        throw $_.exception
    }
}

function HexString-To-Base64
{
    param(
    ## Text of an XML document.
    [Parameter(ValueFromPipeline = $true)]
    [string]$hexString
    )
    try
    {
        $byteArray=HexString-To-ByteArray -hexString $hexString
        return [System.Convert]::ToBase64String($byteArray)
    }catch
    {
        throw $_.exception
    }
}

function HexString-To-Guid
{
    param(
    ## Text of an XML document.
    [Parameter(ValueFromPipeline = $true)]
    [string]$hexString
    )
    try
    {
        $byteArray=HexString-To-ByteArray -hexString $hexString
        return New-Object guid(,([byte[]]$byteArray))
    }catch
    {
        throw $_.exception
    }
}

function SidString-To-ByteArray
{
    param(
    ## Text of an XML document.
    [Parameter(ValueFromPipeline = $true)]
    [string]$sidString
    )
    try
    {
		$sid=New-Object 'Security.Principal.SecurityIdentifier' $sidString
		$x=[System.Byte[]]::CreateInstance([System.Byte],$sid.BinaryLength)
		$sid.GetBinaryForm($x,0)
		$x
	}catch
    {
        throw $_.exception
    }
}



function Get-SHA1
{
    param(
    ## Text of an XML document.
    [Parameter(ValueFromPipeline = $true)]
    [string[]]$Text
    )
    $StringBuilder = New-Object System.Text.StringBuilder
    [System.Security.Cryptography.HashAlgorithm]::Create("SHA1").ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text))|%{
        [Void]$StringBuilder.Append($_.ToString("x2"))
    }
    $StringBuilder.ToString()
}

function Clock
{
    while($true){ Write-Progress $(get-date).ToString("HH:mm:ss") -Activity "Clock"}
}

function StopWatch
{
    $currdate = $(get-date);
    while($true){ Write-Progress $( $(get-date).Add(-$currdate)).ToString("HH:mm:ss.fff") -Activity "StopWatch"}
}

function LoadEXO
{
	$CreateEXOPSSession = "C:\Users\martinr\AppData\Local\Apps\2.0\6BV44X0Q.DAH\A63B7BK7.HA6\micr..tion_1f16bd4ec4c2bb19_0010.0000_673f37c317fb5976"
    if (-not (Test-Path "$CreateEXOPSSession\CreateExoPSSession.ps1" -PathType Leaf))
    {
        $CreateEXOPSSession = (Get-ChildItem -Path $env:userprofile -Filter CreateExoPSSession.ps1 -Recurse -ErrorAction SilentlyContinue -Force | Select -Last 1).DirectoryName
    }
	. "$CreateEXOPSSession\CreateExoPSSession.ps1"
    Connect-EXOPSSession
}

function LoadSCC
{
	$CreateEXOPSSession = "C:\Users\martinr\AppData\Local\Apps\2.0\6BV44X0Q.DAH\A63B7BK7.HA6\micr..tion_1f16bd4ec4c2bb19_0010.0000_673f37c317fb5976"
    if (-not (Test-Path "$CreateEXOPSSession\CreateExoPSSession.ps1" -PathType Leaf))
    {
        $CreateEXOPSSession = (Get-ChildItem -Path $env:userprofile -Filter CreateExoPSSession.ps1 -Recurse -ErrorAction SilentlyContinue -Force | Select -Last 1).DirectoryName
    }
	. "$CreateEXOPSSession\CreateExoPSSession.ps1"
    Connect-IPPSSession
}

function Load-B64Cert
{
    param(
    ## Text of an XML document.
    [Parameter(ValueFromPipeline = $true)]
    [string]$b64EncodedCert
    )
    $b64Formated=$b64EncodedCert;
    $b64Formated=$b64Formated.Replace("-----BEGIN CERTIFICATE-----","");
    $b64Formated=$b64Formated.Replace("-----END CERTIFICATE-----","");
    $b64Formated=$b64Formated.Replace(" ","");
    try
    {
        [byte[]]$derArray=[System.Convert]::FromBase64String($b64Formated)
        $cert=new-object System.Security.Cryptography.X509Certificates.X509Certificate2(,$derArray)
        $cert
    }catch
    {
        throw "Error decoding certificate: $($_.Exception.Message)"
    }

}

function Cleanup-FiddlerCerts
{
    $certs=ls Cert:\CurrentUser\my |?{ `
        $_.issuer -eq "CN=DO_NOT_TRUST_FiddlerRoot, O=DO_NOT_TRUST, OU=Created by http://www.fiddler2.com" `
        -and `
        $_.subject -ne "CN=DO_NOT_TRUST_FiddlerRoot, O=DO_NOT_TRUST, OU=Created by http://www.fiddler2.com"}

    $certs | foreach {certutil -user -delstore my $_.Thumbprint | out-null}
}

function Get-UtcTime
{
    (get-date).ToUniversalTime().ToString("yyyy-MM-ddThh:mm:ssZ")
}

function Get-RemoteCertificate
{
param(
		[Parameter(Mandatory=$true)][string]$computerName,
		[Parameter(Mandatory=$true)][int]$port
)
    $tcpsocket = New-Object Net.Sockets.TcpClient($computerName, $port)
    try
    {
     

        $tcpstream = $tcpsocket.GetStream()
        $sslStream = New-Object System.Net.Security.SslStream($tcpstream,$false,{param($sender, $certificate, $chain, $sslPolicyErrors)return $true})
        $sslStream.AuthenticateAsClient($computerName,$null, [System.Security.Authentication.SslProtocols]::Tls12, $false);        
        if ($sslStream.RemoteCertificate)
        {
            return New-Object system.security.cryptography.x509certificates.x509certificate2($sslStream.RemoteCertificate)
        }else
        {
            throw "Error connecting"
        } 
    }catch
    {
        Write-Error $_.Exception.Message
        Write-Error $_.Exception.InnerException.Message
    }finally
    {
        $tcpsocket.Close();
    }
}

function h
{
    history | select -ExpandProperty CommandLine    
}

function oh
{
    Get-Content "$($env:userprofile)\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
}

# startup

# Since Windows 1809 we have built in history
#
# $HistoryFilePath = Join-Path ([Environment]::GetFolderPath('UserProfile')) .ps_history
# if (Test-path $HistoryFilePath) { Import-Clixml $HistoryFilePath | Add-History }
#


# use Tls12
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# use UTF8
$PSDefaultParameterValues['*:Encoding'] = 'utf8'

Remove-Item Alias:h
Remove-Item Alias:oh -Force

