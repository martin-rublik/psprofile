function LoadEXO
{
	$CreateEXOPSSession = "$($ENV:LOCALAPPDATA)\Apps\2.0\6BV44X0Q.DAH\A63B7BK7.HA6\micr..tion_5329ec537c0b4b5c_0010.0000_9fc624cd0073956e"
    if (-not (Test-Path "$CreateEXOPSSession\CreateExoPSSession.ps1" -PathType Leaf))
    {
        $CreateEXOPSSession = (Get-ChildItem -Path $env:userprofile -Filter CreateExoPSSession.ps1 -Recurse -ErrorAction SilentlyContinue -Force | Select -Last 1).DirectoryName
    }
	. "$CreateEXOPSSession\CreateExoPSSession.ps1"
    Connect-EXOPSSession
}

Function Format-Document
{
    Param([int]$space=4)
    $tab = " " * $space
    $numtab = 0
    
    $text = $psISE.CurrentFile.editor.Text
    foreach ($l in $text -split [environment]::newline)
    {
        $line = $l.Trim()
        if ($line.StartsWith("}") -or $line.EndsWith("}"))
        {
            $numtab -= 1
        }
        $tab = " " * (($space) * $numtab)
        if($line.StartsWith(".") -or $line.StartsWith("< #") -or $line.StartsWith("#>"))
        {
            $tab = $tab.Substring(0, $tab.Length - 1)
        }
        $newText += "{0}{1}" -f (($tab) + $line),[environment]::newline
        if ($line.StartsWith("{") -or $line.EndsWith("{"))
        {
            $numtab += 1
        }
        if ($numtab -lt 0)
        {
            $numtab = 0
        }
    }
    $psISE.CurrentFile.Editor.Clear()
    $psISE.CurrentFile.Editor.InsertText($newText)
}

# Define the script block that will execute every time a new PowerShell tab is opened.
# We have to do this, because the keyboard mapping is configure per-PowerShell tab. Therefore,
# each time a new PowerShell tab is opened, we must perform create the keyboard mapping.

# NOTE: There is a bug
$ScriptBlock =
{
    # Define the script block that will execute for our ISE menu add-on
    $CloseFileScriptBlock =
    {
        Format-Document
    }
    
    # Define the key gesture we’ll use to close the active ISE script tab
    $KeyGesture = New-Object `
    -TypeName System.Windows.Input.KeyGesture `
    -ArgumentList ([System.Windows.Input.Key]::K, [System.Windows.Input.ModifierKeys]::Control);
    
    # IMPORTANT: Without this try .. catch block around the foreach loop, this code will likely fail
    # IF someone tries to open too many PowerShell tabs in too short a period of time. If they do,
    # the $psise.PowerShellTabs collection will be modified WHILE it is being iterated over. If
    # this happens, then the event subscriber will be set to a FAILED state and will not execute
    # as desired.
    try
    {
        # Iterate over PowerShell tabs and add the shortcut
        foreach ($IseTab in $psise.PowerShellTabs)
        {
            try
            {
                [void] $IseTab.AddOnsMenu.Submenus.Add("Format Document", $CloseFileScriptBlock, $KeyGesture);
            }
            catch
            {
                # Write-Host -Object (‘Error occurred adding menu item and keyboard shortcut mapping for PowerShell tab: {0}’ -f $IseTab.DisplayName);
            }
        }
    }
    catch
    {
        Write-Host -Object "Error occurred while iterating over PowerShell tabs.";
    }
}

# Unregister all event subscriptions. Can’t find a way to identify specifically which event
# subscription is being used for this purpose.
Get-EventSubscriber -SourceIdentifier IsePowerShellTabs -ErrorAction SilentlyContinue | Unregister-Event;
[void] (Register-ObjectEvent -InputObject $psise.PowerShellTabs -EventName CollectionChanged -Action $ScriptBlock -SourceIdentifier IsePowerShellTabs);
Invoke-Command -ScriptBlock $ScriptBlock;




