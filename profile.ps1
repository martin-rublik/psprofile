# custom globals
$global:CLOUDTENANT=$null

function checkLastCommand
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
    if ($lastCommand.ToLower().StartsWith("connect-aadrmservice"))
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
	if ($HistoryFilePath)
	{
		try
		{
			Get-History | Export-Clixml $HistoryFilePath
		}catch
		{
			Write-Warning "Error writing the history $($_.Exception)"
		}
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
        $host.ui.RawUI.WindowTitle = "PS @MSOL:$($global:CLOUDTENANT.Name)"
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
	$CreateEXOPSSession = "C:\Users\martinr\AppData\Local\Apps\2.0\TWGVB7P4.1EJ\J3ZCK219.TVM\micr..tion_a8eee8aa09b0c4a7_0010.0000_48ffb9840f84f528"
    if (-not (Test-Path "$CreateEXOPSSession\CreateExoPSSession.ps1" -PathType Leaf))
    {
        $CreateEXOPSSession = (Get-ChildItem -Path $env:userprofile -Filter CreateExoPSSession.ps1 -Recurse -ErrorAction SilentlyContinue -Force | Select -Last 1).DirectoryName
    }
	. "$CreateEXOPSSession\CreateExoPSSession.ps1"
    Connect-EXOPSSession
}


# startup

$HistoryFilePath = Join-Path ([Environment]::GetFolderPath('UserProfile')) .ps_history
#Register-EngineEvent PowerShell.Exiting -Action { Get-History | Export-Clixml $HistoryFilePath } | out-null
if (Test-path $HistoryFilePath) { Import-Clixml $HistoryFilePath | Add-History }

# use Tls12
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# use UTF8
$PSDefaultParameterValues['*:Encoding'] = 'utf8'


