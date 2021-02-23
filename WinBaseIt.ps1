##########################################################################
# This checks to see if script is running as admin, then spawns if not ***
##########################################################################
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))

{   

$arguments = "& '" + $myinvocation.mycommand.definition + "'"

Start-Process powershell -Verb runAs -ArgumentList $arguments

Break

}

# Hide PowerShell Console
Add-Type -Name Window -Namespace Console -MemberDefinition '
[DllImport("Kernel32.dll")]
public static extern IntPtr GetConsoleWindow();
[DllImport("user32.dll")]
public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
'
$consolePtr = [Console.Window]::GetConsoleWindow()
[Console.Window]::ShowWindow($consolePtr, 0)

##########################################################################
# ****** This allows for dialog boxes to be utilized in the script *******
##########################################################################
[reflection.assembly]::LoadWithPartialName("System.Windows.Forms")
[void][System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic')

##########################################################################
# **************** creates temp folder and hostname folder ***************
##########################################################################
$a = hostname
$d1 = date -Format MM-dd-yy
$d2 = date -Format hh-mm-ss
$c = $a + "_" + $d1 + "_" + $d2

New-Item -Path "c:\" -Name "temp" -ItemType "directory" -ErrorAction SilentlyContinue | Out-Null
New-Item -Path "c:\temp" -Name "$c" -ItemType "directory" -ErrorAction SilentlyContinue | Out-Null
$temppath = "c:\temp\$c"

##########################################################################
# ******************** This is the gui container *************************
##########################################################################
$folderForm = New-Object System.Windows.Forms.Form
$folderForm.Text = "WinBaseIt ~ Baselining Tool"
$folderForm.Size = "365,190"


##########################################################################
# **************** This adds the Net button to the gui ******************* 
##########################################################################
$NetButton = New-Object System.Windows.Forms.Button
$NetButton.Text = 'Network'
$NetButton.Location = '23,23'

##########################################################################
# *********** This makes the Net button perform Network Baseling *********
##########################################################################

$NetButton.Add_Click({
    [System.Windows.MessageBox]::Show('Getting ipconfig, arp, route, netstat')
    New-Item -Path $temppath -Name "Network" -ItemType "directory" -ErrorAction SilentlyContinue | Out-Null
    $temppathnet = "$temppath\Network"
    ipconfig /all > $temppathnet\ipconfig.txt | Out-Null
    arp -a > $temppathnet\arp.txt | Out-Null
    route print > $temppathnet\route.txt | Out-Null
    netstat -bano > $temppathnet\netstat.txt | Out-Null

})

$folderForm.Controls.Add($NetButton)

##########################################################################
# **************** This adds SysInfo button to the gui ****************** 
##########################################################################
$sysButton = New-Object System.Windows.Forms.Button

$sysButton.Text = 'SysInfo'
$sysButton.Location = '100,23'

$folderForm.Controls.Add($sysButton)

##########################################################################
# ******* This makes the SysInfo Button Collect System Information *******
##########################################################################
$sysButton.Add_Click({
    [System.Windows.MessageBox]::Show('Getting Date and System Information')
    New-Item -Path $temppath -Name "System-Information" -ItemType "directory" -ErrorAction SilentlyContinue | Out-Null
    $temppathsys = "$temppath\System-Information"
    Get-Date > $temppathsys\systeminfo.txt | Out-Null
    systeminfo >> $temppathsys\systeminfo.txt | Out-Null
})

##########################################################################
# ************* This adds Audit Policy button to the gui ***************** 
##########################################################################
$audpolButton = New-Object System.Windows.Forms.Button

$audpolButton.Text = "Audit Policy"
$audpolButton.Location = '177,23'

$folderForm.Controls.Add($audpolButton)

##########################################################################
# **** This makes the Audit Pol Button grab all the audit policies *******
##########################################################################
$audpolButton.Add_Click({
    [System.Windows.MessageBox]::Show('Getting Audit Policy')
    $c = "Audit-Policy"
    New-Item -Path $temppath -Name $c -ItemType "directory" -ErrorAction SilentlyContinue | Out-Null
    $temppathaudpol = "$temppath\$c"
    auditpol /get /category:* > $temppathaudpol\auditpolicy.txt | Out-Null
    If ((Get-Content "$temppathaudpol\auditpolicy.txt") -eq $Null) {
        [System.Windows.MessageBox]::Show('Error Occured. Make sure you are running this program with Administrative Privilages','  Audit Policy','OK','Error')
        }
})

##########################################################################
# ***************** This adds processes button to the gui **************** 
##########################################################################
$procButton = New-Object System.Windows.Forms.Button

$procButton.Text = 'Processes'
$procButton.Location = '254,23'

$folderForm.Controls.Add($procButton)

##########################################################################
# ******** This makes the proccesses Button get running processes ********
##########################################################################
$procButton.Add_Click({
    [System.Windows.MessageBox]::Show('Getting Running Processes')
    $c = "Processes"
    New-Item -Path $temppath -Name $c -ItemType "directory" -ErrorAction SilentlyContinue | Out-Null
    $temppathproc = "$temppath\$c"
    gwmi win32_process |select processname,ProcessID,ParentProcessID,CommandLine,@{e={$_.GetOwner().User}} | Sort processname > $temppathproc\process_list.txt | Out-Null
    If ((Get-Content "$temppathproc\process_list.txt") -eq $Null) {
        [System.Windows.MessageBox]::Show('Error Occured. Make sure you are running this program with Administrative Privilages','  Processes','OK','Error')
        }
})

##########################################################################
# ***************** This adds Services button to the gui **************** 
##########################################################################
$servButton = New-Object System.Windows.Forms.Button

$servButton.Text = 'Services'
$servButton.Location = '23,53'

$folderForm.Controls.Add($servButton)

##########################################################################
# ********** This makes the Services Button get running Services *********
##########################################################################
$servButton.Add_Click({
    [System.Windows.MessageBox]::Show('Getting List of Services')
    $c = "Services"
    New-Item -Path $temppath -Name $c -ItemType "directory" -ErrorAction SilentlyContinue | Out-Null
    $temppathserv = "$temppath\$c"
    Get-Service > $temppathserv\services.txt | Out-Null
    If ((Get-Content "$temppathserv\services.txt") -eq $Null) {
        [System.Windows.MessageBox]::Show('Error Occured. Make sure you are running this program with Administrative Privilages','  Services','OK','Error')
        }
})

##########################################################################
# ***************** This adds Users button to the gui ******************** 
##########################################################################
$userButton = New-Object System.Windows.Forms.Button

$userButton.Text = 'Users'
$userButton.Location = '100,53'

$folderForm.Controls.Add($userButton)

##########################################################################
# ********* This makes the users Button get a list of all users **********
##########################################################################
$userButton.Add_Click({
    [System.Windows.MessageBox]::Show('Getting List of Users')
    $c = "Users"
    New-Item -Path $temppath -Name $c -ItemType "directory" -ErrorAction SilentlyContinue | Out-Null
    $temppathusers = "$temppath\$c"
    net users > $temppathusers\users.txt | Out-Null
    If ((Get-Content "$temppathusers\users.txt") -eq $Null) {
        [System.Windows.MessageBox]::Show('Error Occured. Make sure you are running this program with Administrative Privilages','  Users','OK','Error')
        }
})

##########################################################################
# *********** This adds Firewall Rules button to the gui *****************
##########################################################################
$frButton = New-Object System.Windows.Forms.Button

$frButton.Text = 'Firewall'
$frButton.Location = '177,53'

$folderForm.Controls.Add($frButton)

##########################################################################
# ****** This makes the Firewall Rules Button get a list of all Rules ****
##########################################################################
$frButton.Add_Click({
    [System.Windows.MessageBox]::Show('Getting List of Firewall Rules')
    $c = "Firewall"
    New-Item -Path $temppath -Name $c -ItemType "directory" -ErrorAction SilentlyContinue | Out-Null
    $temppathfr = "$temppath\$c"
    netsh advfirewall firewall show rule name = all > $temppathfr\firewall_rules.txt 
    If ((Get-Content "$temppathfr\firewall_rules.txt") -eq $Null) {
        [System.Windows.MessageBox]::Show('Error Occured. Make sure you are running this program with Administrative Privilages','  Firewall Rules','OK','Error')
        }
})

##########################################################################
# *********** This adds Prefetch button to the gui *****************
##########################################################################
$preButton = New-Object System.Windows.Forms.Button

$preButton.Text = 'Prefetch'
$preButton.Location = '254,53'

$folderForm.Controls.Add($preButton)

##########################################################################
# * This makes the Prefetch Button get a list of all Windows Prefetches **
##########################################################################
$preButton.Add_Click({
    [System.Windows.MessageBox]::Show('Getting List of Windows Prefetch')
    $c = "Prefetch"
    New-Item -Path $temppath -Name $c -ItemType "directory" -ErrorAction SilentlyContinue | Out-Null
    $temppathpre = "$temppath\$c"
    Get-ChildItem C:\Windows\Prefetch | sort > $temppathpre\prefetch_listing.txt | Out-Null 
    If ((Get-Content "$temppathpre\prefetch_listing.txt") -eq $Null) {
        [System.Windows.MessageBox]::Show('Error Occured. Make sure you are running this program with Administrative Privilages','  Prefetch','OK','Error')
        }
})

##########################################################################
# ***************** This adds Installed App button to the gui ************ 
##########################################################################
$iaButton = New-Object System.Windows.Forms.Button

$iaButton.Text = 'Applications'
$iaButton.Location = '23,84'

$folderForm.Controls.Add($iaButton)

##########################################################################
# ** This makes the Applications Button get all apps found in registry ***
##########################################################################
$iaButton.Add_Click({
    [System.Windows.MessageBox]::Show('Getting List of Installed Applications, and Start Up Applications')
    $c = "Applications"
    New-Item -Path $temppath -Name $c -ItemType "directory" -ErrorAction SilentlyContinue | Out-Null
    $temppathia = "$temppath\$c"
    
    $PATHS = @("HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
           "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
    $SOFTWARE = "SOFTWARE_NAME"
    $installapp = ForEach ($path in $PATHS) {
                    Get-ChildItem -Path $path |
                    ForEach { Get-ItemProperty $_.PSPath } |
                    Select-Object -Property DisplayName,DisplayIcon,DisplayVersion,Publisher,InstallDate,InstallSource,InstallLocation,Version |
                    Where-Object {$_.displayname -NE $null -or $_.DisplayIcon -NE $null -or $_.InstallLocation -NE $null }
                  }
    $installapp | Sort-Object DisplayName > $temppathia\installed_apps.txt

    Get-WmiObject Win32_StartupCommand | select-object -property name,command,location | Sort-Object Name | Format-List > $temppathia\startup_apps.txt | Out-Null
    If ((Get-Content "$temppathia\installed_apps.txt") -eq $Null) {
        [System.Windows.MessageBox]::Show('Error Occured. Make sure you are running this program with Administrative Privilages','  Applications','OK','Error')
        }
    If ((Get-Content "$temppathia\startup_apps.txt") -eq $Null) {
        [System.Windows.MessageBox]::Show('Error Occured. Make sure you are running this program with Administrative Privilages','  Applications','OK','Error')
        }
})

##########################################################################
# ***************** This adds Tasks button to the gui ******************** 
##########################################################################
$taskButton = New-Object System.Windows.Forms.Button

$taskButton.Text = 'Sch Tasks'
$taskButton.Location = '100,84'

$folderForm.Controls.Add($taskButton)

##########################################################################
# ******* This makes the tasks Button get a list of scheduled Tasks ******
##########################################################################
$taskButton.Add_Click({
    [System.Windows.MessageBox]::Show('Getting List of Scheduled Tasks')
    $c = "Scheduled_Tasks"
    New-Item -Path $temppath -Name $c -ItemType "directory" -ErrorAction SilentlyContinue | Out-Null
    $temppathtask = "$temppath\$c"
    schtasks /query /FO list /v > $temppathtask\schedule_tasks.txt | Out-Null
    If ((Get-Content "$temppathtask\schedule_tasks.txt") -eq $Null) {
        [System.Windows.MessageBox]::Show('Error Occured. Make sure you are running this program with Administrative Privilages','  Scheduled Tasks','OK','Error')
        }
})


##########################################################################
# *********** This adds Drives Rules button to the gui *****************
##########################################################################
$drButton = New-Object System.Windows.Forms.Button

$drButton.Text = 'Drives'
$drButton.Location = '177,84'

$folderForm.Controls.Add($drButton)

##########################################################################
# * This makes the Drives Button get a list of physical & logical drives *
##########################################################################
$drButton.Add_Click({
    [System.Windows.MessageBox]::Show('Getting List Of All Physical And Logical Drives')
    $c = "Drives"
    New-Item -Path $temppath -Name $c -ItemType "directory" -ErrorAction SilentlyContinue | Out-Null
    $temppathdr = "$temppath\$c"

    $DriveType = @{
        Name = 'DriveType'
        Expression = {
        # property is an array, so process all values
        $value = $_.DriveType
    
        switch([int]$value)
            {
                0          {'Unknown'}
                1          {'No Root Directory'}
                2          {'Removable Disk'}
                3          {'Local Disk'}
                4          {'Network Drive'}
                5          {'Compact Disc'}
                6          {'RAM Disk'}
                default    {"$value"}
            }
      
        }  
    }
    Get-WmiObject -Class Win32_logicaldisk | Select-Object -Property DeviceID, $DriveType, VolumeName, @{L='FreeSpaceGB';E={"{0:N2}" -f ($_.FreeSpace /1GB)}}, @{L="Capacity";E={"{0:N2}" -f($_.Size/1GB)}}, ProviderName > $temppathdr\drives.txt | Out-Null
    net share > $temppathdr\net_shares.txt | Out-Null
    
    If ((Get-Content "$temppathdr\net_shares.txt") -eq $Null) {
        [System.Windows.MessageBox]::Show('Error Occured. Make sure you are running this program with Administrative Privilages','  Drives','OK','Error')
        }
    If ((Get-Content "$temppathdr\drives.txt") -eq $Null) {
        [System.Windows.MessageBox]::Show('Error Occured. Make sure you are running this program with Administrative Privilages','  Drives','OK','Error')
        }
})

##########################################################################
# ************* This adds Sys32 Dir Walk button to the gui ***************
##########################################################################
$dwButton = New-Object System.Windows.Forms.Button

$dwButton.Text = 'Sys32 Dir'
$dwButton.Location = '254,84'

$folderForm.Controls.Add($dwButton)

##########################################################################
# This makes the Sys32 Dir Button get a list of all Windows folder & files
##########################################################################
$dwButton.Add_Click({
    [System.Windows.MessageBox]::Show('Getting Directory Walk of System32.  This could take a bit')
    $c = "System32-Directory-Walk"
    New-Item -Path $temppath -Name $c -ItemType "directory" -ErrorAction SilentlyContinue | Out-Null
    $temppathdw = "$temppath\$c"
    Get-ChildItem C:\Windows\System32 -Recurse > $temppathdw\dir_system32.txt | Out-Null
    Start-Sleep -s 30
    If ((Get-Content "$temppathdw\dir_system32.txt") -eq $Null) {
        [System.Windows.MessageBox]::Show('Error Occured. Make sure you are running this program with Administrative Privilages','  Sys32','OK','Error')
        }
})

##########################################################################
# ***************** This adds Defender button to the gui **************** 
##########################################################################
$defButton = New-Object System.Windows.Forms.Button

$defButton.Text = 'Defender'
$defButton.Location = '23,115'

$folderForm.Controls.Add($defButton)

##########################################################################
# ********** This makes the Defender Button get running Services *********
##########################################################################
$defButton.Add_Click({
    [System.Windows.MessageBox]::Show('Getting copy of Windows Defender Cab file.  This could take a bit.')
    $c = "Windows-Defender"
    New-Item -Path $temppath -Name $c -ItemType "directory" -ErrorAction SilentlyContinue | Out-Null
    $temppathdef = "$temppath\$c"
    cmd /c "c:\Program Files\Windows Defender\MpCmdRun.exe" -GetFiles 
    Copy-Item  -Path "C:\ProgramData\Microsoft\Windows Defender\Support\MpSupportFiles.cab" -Destination $temppathdef
    Start-Sleep -s 30
    If ((Get-Content "$temppathdef\MpSupportFiles.cab") -eq $Null) {
        [System.Windows.MessageBox]::Show('Error Occured. Make sure you are running this program with Administrative Privilages','  Defender','OK','Error')
        }
})

##########################################################################
# ********* This adds Baseline   Entire   Machine button to the gui ********** 
##########################################################################
$baseallButton = New-Object System.Windows.Forms.Button

$baseallButton.Text = 'Baseline  Entire  Machine'
$baseallButton.Size = '230,23'
$baseallButton.Location = '100,115'
$baseallButton.BackColor = 'Green'

$folderForm.Controls.Add($baseallButton)

##########################################################################
# ******* This makes the tasks Button get a list of scheduled Tasks ******
##########################################################################
$baseallButton.Add_Click({
    [System.Windows.MessageBox]::Show('Getting List of Scheduled Tasks')
    New-Item -Path $temppath -Name "Applications" -ItemType "directory" -ErrorAction SilentlyContinue | Out-Null
    New-Item -Path $temppath -Name "Audit-Policy" -ItemType "directory" -ErrorAction SilentlyContinue | Out-Null
    New-Item -Path $temppath -Name "Drives" -ItemType "directory" -ErrorAction SilentlyContinue | Out-Null
    New-Item -Path $temppath -Name "Firewall" -ItemType "directory" -ErrorAction SilentlyContinue | Out-Null
    New-Item -Path $temppath -Name "Network" -ItemType "directory" -ErrorAction SilentlyContinue | Out-Null
    New-Item -Path $temppath -Name "Prefetch" -ItemType "directory" -ErrorAction SilentlyContinue | Out-Null
    New-Item -Path $temppath -Name "Processes" -ItemType "directory" -ErrorAction SilentlyContinue | Out-Null
    New-Item -Path $temppath -Name "Scheduled_Tasks" -ItemType "directory" -ErrorAction SilentlyContinue | Out-Null
    New-Item -Path $temppath -Name "Services" -ItemType "directory" -ErrorAction SilentlyContinue | Out-Null
    New-Item -Path $temppath -Name "System32-Directory-Walk" -ItemType "directory" -ErrorAction SilentlyContinue | Out-Null
    New-Item -Path $temppath -Name "System-Information" -ItemType "directory" -ErrorAction SilentlyContinue | Out-Null
    New-Item -Path $temppath -Name "Users" -ItemType "directory" -ErrorAction SilentlyContinue | Out-Null
    New-Item -Path $temppath -Name "Windows-Defender" -ItemType "directory" -ErrorAction SilentlyContinue | Out-Null
    
    #systeminfo - DONE
    Get-Date > $temppath\System-Information\systeminfo.txt | Out-Null
    systeminfo >> $temppath\System-Information\systeminfo.txt | Out-Null
    
    #Audit Policy - DONE
    auditpol /get /category:* > $temppath\Audit-Policy\auditpolicy.txt | Out-Null
    
    #Network Settings  - DONE
    ipconfig /all > $temppath\Network\ipconfig.txt | Out-Null
    arp -a > $temppath\Network\arp.txt | Out-Null
    route print > $temppath\Network\route.txt | Out-Null
    netstat -bano > $temppath\Network\netstat.txt | Out-Null
    
    #Processes - Done
    gwmi win32_process |select processname,ProcessID,ParentProcessID,CommandLine,@{e={$_.GetOwner().User}} | Sort processname > $temppath\Processes\process_list.txt | Out-Null
    
    #services - Done
    Get-Service > $temppath\Services\services.txt | Out-Null
    
    #Users - Done
    net users > $temppath\Users\users.txt | Out-Null
    
    #Firewall Rules - Done
    netsh advfirewall firewall show rule name = all > $temppath\Firewall\firewall_rules.txt | Out-Null
    
    #prefetch - Done
    Get-ChildItem C:\Windows\Prefetch | sort > $temppath\Prefetch\prefetch_listing.txt | Out-Null
    
    #Installed Apps - Done
    $PATHS = @("HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
    $SOFTWARE = "SOFTWARE_NAME"
    $installapp = ForEach ($path in $PATHS) {
                    Get-ChildItem -Path $path |
                        ForEach { Get-ItemProperty $_.PSPath } |
                        Select-Object -Property DisplayName,DisplayIcon,DisplayVersion,Publisher,InstallDate,InstallSource,InstallLocation,Version |
                        Where-Object {$_.displayname -NE $null -or $_.DisplayIcon -NE $null -or $_.InstallLocation -NE $null }
                }
    $installapp | Sort-Object DisplayName > $temppath\Applications\installed_apps.txt
    
    #Startup Apps - Done
    Get-WmiObject Win32_StartupCommand | select-object -property name,command,location | Sort-Object Name | Format-List > $temppath\Applications\startup_apps.txt | Out-Null
    
    #Scheduled Tasks - Done
    schtasks /query /FO list /v > $temppath\Scheduled_Tasks\scheduled_tasks.txt | Out-Null
    
    #Drives (Logical / Physical) - Done
    $DriveType = @{
    Name = 'DriveType'
    Expression = {
        # property is an array, so process all values
        $value = $_.DriveType
        
        switch([int]$value)
        {
            0          {'Unknown'}
            1          {'No Root Directory'}
            2          {'Removable Disk'}
            3          {'Local Disk'}
            4          {'Network Drive'}
            5          {'Compact Disc'}
            6          {'RAM Disk'}
            default    {"$value"}
        }
          
    }  
    }
    Get-WmiObject -Class Win32_logicaldisk | Select-Object -Property DeviceID, $DriveType, VolumeName, @{L='FreeSpaceGB';E={"{0:N2}" -f ($_.FreeSpace /1GB)}}, @{L="Capacity";E={"{0:N2}" -f($_.Size/1GB)}}, ProviderName > $temppath\Drives\drives.txt | Out-Null
    net share > $temppath\Drives\net_shares.txt | Out-Null
    
    #Dir Walk c:\windows\system32
    Get-ChildItem C:\Windows\System32 -Recurse > $temppath\System32-Directory-Walk\dir_system32.txt | Out-Null
    
    #Windows Defender Files
    cmd /c "c:\Program Files\Windows Defender\MpCmdRun.exe" -GetFiles | Out-Null
    Copy-Item  -Path "C:\ProgramData\Microsoft\Windows Defender\Support\MpSupportFiles.cab" -Destination $temppath\Windows-Defender\Win_Defender.cab | Out-Null    
      
})

##########################################################################
# ****** This is the end that shows everything above on one nice gui *****
##########################################################################
$folderForm.ShowDialog()