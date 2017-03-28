<#
    Created:	 2017-01-02
    Version:	 1.0
    Author       Dave Kawula MVP and Thomas Rayner MVP
    Homepage:    http://www.checkyourlogs.net

    Disclaimer:
    This script is provided "AS IS" with no warranties, confers no rights and 
    is not supported by the authors or DeploymentArtist.

    Author - Dave Kawula
    Twitter: @DaveKawula
    Blog   : http://www.checkyourlogs.net

    Author - Thomas Rayner
    Twitter: @MrThomasRayner
    Blog   : http://workingsysadmin.com


    .Synopsis
    Creates a big demo lab.
    .DESCRIPTION
    Huge Thank you to Ben Armstrong @VirtualPCGuy for giving me the source starter code for this :)
    This script will build a sample lab configruation on a single Hyper-V Server:

    It includes in this version 2 Domain Controllers, 1 x DHCP1, 1 x MGMT Server, 16 x S2D Nodes

    It is fully customizable as it has been created with base functions.

    The Parameters at the beginning of the script will setup the domain name, organization name etc.

    You will need to change the <ProductKey> Variable as it has been removed for the purposes of the print in this book.

    .EXAMPLE
    TODO: Dave, add something more meaningful in here
    .PARAMETER WorkingDir
    Transactional directory for files to be staged and written
    .PARAMETER Organization
    Org that the VMs will belong to
    .PARAMETER Owner
    Name to fill in for the OSs Owner field
    .PARAMETER TimeZone
    Timezone used by the VMs
    .PARAMETER AdminPassword
    Administrative password for the VMs
    .PARAMETER DomainName
    AD Domain to setup/join VMs to
    .PARAMETER DomainAdminPassword
    Domain recovery/admin password
    .PARAMETER VirtualSwitchName
    Name of the vSwitch for Hyper-V
    .PARAMETER Subnet
    The /24 Subnet to use for Hyper-V networking
#>

[cmdletbinding()]
param
( 
  [Parameter(Mandatory)]
  [ValidateScript({
        $_ -match '[^\\]$' 
  })] #ensure WorkingDir does not end in a backslash, otherwise issues are going to come up below
  [string]
  $WorkingDir = 'c:\ClusterStoreage\Volume1\DCBuild',

  [Parameter(Mandatory)]
  [string]
  $Organization = 'MVP Rockstars',

  [Parameter(Mandatory)]
  [string]
  $Owner = 'Dave Kawula',

  [Parameter(Mandatory)]
  [ValidateScript({
        $_ -in ([System.TimeZoneInfo]::GetSystemTimeZones()).ID 
  })] #ensure a valid TimeZone was passed
  [string]
  $Timezone = 'Pacific Standard Time',

  [Parameter(Mandatory)]
  [string]
  $adminPassword = 'P@ssw0rd',

  [Parameter(Mandatory)]
  [string]
  $domainName = 'MVPDays.Com',

  [Parameter(Mandatory)]
  [string]
  $domainAdminPassword = 'P@ssw0rd', # This is not a preferred way to do passwords.

  [Parameter(Mandatory)]
  [string]
  $virtualSwitchName = 'Dave MVP Demo',

  [Parameter(Mandatory)]
  [ValidatePattern('(\d{1,3}\.){3}')] #ensure that Subnet is formatted like the first three octets of an IPv4 address
  [string]
  $Subnet = '172.16.200.',

  [Parameter(Mandatory)]
  [string]
  $ExtraLabfilesSource = 'C:\ClusterStorage\Volume1\DCBuild\Extralabfiles'


)

#region Functions

function Wait-PSDirect
{
  param
  (
    [string]
    $VMName,

    [Object]
    $cred
  )

  Write-Log $VMName "Waiting for PowerShell Direct (using $($cred.username))"
  while ((Invoke-Command -VMName $VMName -Credential $cred {
        'Test'
  } -ea SilentlyContinue) -ne 'Test') 
  {
    Start-Sleep -Seconds 1
  }
}


function Wait-Sleep 
{
  param (
    [int]$sleepSeconds = 60
  )
  
  Write-Log "Waiting for $sleepSeconds seconds"

  for ($sleep = 1; $sleep -le $sleepSeconds; $sleep++ ) 
  {
    Write-Progress -ParentId -1 -Id 42 -Activity "Sleeping for $sleepSeconds seconds" -Status "Slept for $sleep Seconds:" -PercentComplete (($sleep / $sleepSeconds) * 100)
    Start-Sleep -Seconds 1
  }
  Write-Progress -Completed -Id 42 -Activity 'Done Sleeping'
}
    

function Restart-DemoVM
{
  param
  (
    [string]$VMName
  )

  Write-Log $VMName 'Rebooting'
  Stop-VM $VMName
  Start-VM $VMName
}

function Confirm-Path
{
  param
  (
    [string] $Location
  )
  
  if (!(Test-Path $Location)) 
  {
    $null = New-Item -Type Directory -Path $Location
  }
}

function Write-Log 
{
  param
  (
    [string]$systemName,
    [string]$message
  )

  Write-Output "[$(Get-Date -format T)] - [$systemName]::$($message)"
}

function Clear-File
{
  param
  (
    [string] $file
  )
    
  if (Test-Path $file) 
  {
    $null = Remove-Item $file -Recurse -Force
  }
}

function Get-UnattendChunk 
{
  param
  (
    [string] $pass, 
    [string] $component, 
    [xml] $unattend
  ) 
    
  $unattend.unattend.settings |
    Where-Object -Property pass -EQ -Value $pass |
    Select-Object -ExpandProperty component |
    Where-Object -Property name -EQ -Value $component
}

function New-UnattendFile 
{
  param
  (
    [string] $filePath
  ) 

  $unattend = $unattendSource.Clone()
  Get-UnattendChunk 'specialize' 'Microsoft-Windows-Shell-Setup' $unattend | ForEach-Object -Process {
    $_.RegisteredOrganization = 'Azure Sea Class Covert Trial' #TR-Egg
    $_.RegisteredOwner = 'Thomas Rayner - @MrThomasRayner - workingsysadmin.com' #TR-Egg
    $_.TimeZone = $Timezone
    $_.ProductKey = $WindowsKey
  }
  Get-UnattendChunk 'oobeSystem' 'Microsoft-Windows-Shell-Setup' $unattend | ForEach-Object -Process {
    $_.UserAccounts.AdministratorPassword.Value = $adminPassword
  }

  Clear-File $filePath
  $unattend.Save($filePath)
}

function Initialize-BaseImage
{
  Mount-DiskImage $ServerISO
  $DVDDriveLetter = (Get-DiskImage $ServerISO | Get-Volume).DriveLetter
  Copy-Item -Path "$($DVDDriveLetter):\NanoServer\NanoServerImageGenerator\Convert-WindowsImage.ps1" -Destination "$($WorkingDir)\Convert-WindowsImage.ps1" -Force
  Import-Module -Name "$($DVDDriveLetter):\NanoServer\NanoServerImagegenerator\NanoServerImageGenerator.psm1" -Force
   
   
  if (!(Test-Path -Path "$($BaseVHDPath)\NanoBase.vhdx")) 
  {
    New-NanoServerImage -MediaPath "$($DVDDriveLetter):\" -BasePath $BaseVHDPath -TargetPath "$($BaseVHDPath)\NanoBase.vhdx" -Edition Standard -DeploymentType Guest -Compute -Clustering -AdministratorPassword (ConvertTo-SecureString -String $adminPassword -AsPlainText -Force)
  }
    
  New-UnattendFile "$WorkingDir\unattend.xml"

  if (!(Test-Path -Path "$($BaseVHDPath)\VMServerBaseCore.vhdx")) 
  {
    Set-Location $WorkingDir 

    . .\Convert-WindowsImage.ps1 
    $ConvertWindowsImageParam = @{
      SourcePath          = $ServerISO
      RemoteDesktopEnable = $True
      Passthru            = $True
      Edition             = 'ServerDataCenterCore'
      VHDFormat           = 'VHDX'
      SizeBytes           = 60GB
      WorkingDirectory    = $WorkingDir
      VHDPath             = "$($BaseVHDPath)\VMServerBaseCore.vhdx"
      DiskLayout          = 'UEFI'
      UnattendPath        = "$($WorkingDir)\unattend.xml"
    }

    $VHDx = Convert-WindowsImage @ConvertWindowsImageParam
  }
    
  if (!(Test-Path -Path "$($BaseVHDPath)\VMServerBase.vhdx")) 
  {
    Set-Location $WorkingDir 

    . .\Convert-WindowsImage.ps1 
    $ConvertWindowsImageParam = @{
      SourcePath          = $ServerISO
      RemoteDesktopEnable = $True
      Passthru            = $True
      Edition             = 'ServerDataCenter'
      VHDFormat           = 'VHDX'
      SizeBytes           = 60GB
      WorkingDirectory    = $WorkingDir
      VHDPath             = "$($BaseVHDPath)\VMServerBase.vhdx"
      DiskLayout          = 'UEFI'
      UnattendPath        = "$($WorkingDir)\unattend.xml"
    }

    $VHDx = Convert-WindowsImage @ConvertWindowsImageParam
  }
            
  Clear-File "$($BaseVHDPath)\unattend.xml"
  Dismount-DiskImage $ServerISO 
  Clear-File "$($WorkingDir)\Convert-WindowsImage.ps1"
}

function Invoke-DemoVMPrep 
{
  param
  (
    [string] $VMName, 
    [string] $GuestOSName, 
    [switch] $FullServer
  ) 

  Write-Log $VMName 'Removing old VM'
    Get-VM $VMName -ErrorAction SilentlyContinue |
    Stop-VM -TurnOff -Force -Passthru |
    Remove-VM -Force
  Clear-File "$($VMPath)\$($GuestOSName).vhdx"
   
  Write-Log $VMName 'Creating new differencing disk'
  
  $vhdxName = 'VMServerBase.vhdx'
  <#>if ($FullServer)
  {
    $FullServer = 'VMServerBase.vhdx'
  }</#>
  
  $null = New-VHD -Path "$($VMPath)\$($GuestOSName).vhdx" -ParentPath "C:\clusterstorage\volume1\dcbuild\basevhds\VMServerBase.vhdx" -Differencing

  Write-Log $VMName 'Creating virtual machine'
  New-VM -Name $VMName -MemoryStartupBytes 16GB -SwitchName $virtualSwitchName -Generation 2 -Path "$($VMPath)\" |
  Set-VM -ProcessorCount 2 
  Write-Log $VMName 'Configuring Dynamic Memory'
  #Set-VMMemory -VMName $VMName -DynamicMemoryEnabled $true -MinimumBytes 512MB -MaximumBytes 16GB -StartupBytes 8GB
  Write-Log $VMName 'Enable UEFI'
  Set-VMFirmware -VMName $VMName -SecureBootTemplate MicrosoftUEFICertificateAuthority
  Set-VMFirmware -Vmname $VMName -EnableSecureBoot off
  Add-VMHardDiskDrive -VMName $VMName -Path "$($VMPath)\$($GuestOSName).vhdx" -ControllerType SCSI
  Write-Log $VMName 'Starting virtual machine'
  Enable-VMIntegrationService -Name 'Guest Service Interface' -VMName $VMName
  Start-VM $VMName
}

function New-DemoVM 
{
  param
  (
    [string] $VMName, 
    [string] $GuestOSName, 
    [string] $IPNumber = '0'
  ) 
  
  Wait-PSDirect $VMName -cred $localCred

  Invoke-Command -VMName $VMName -Credential $localCred {
    param($IPNumber, $GuestOSName,  $VMName, $domainName, $Subnet)
    if ($IPNumber -ne '0') 
    {
      Write-Output -InputObject "[$($VMName)]::Setting IP Address to $($Subnet)$($IPNumber)"
      $null = New-NetIPAddress -IPAddress "$($Subnet)$($IPNumber)" -InterfaceAlias 'Ethernet' -PrefixLength 24
      Write-Output -InputObject "[$($VMName)]::Setting DNS Address"
      Get-DnsClientServerAddress | ForEach-Object -Process {
        Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ServerAddresses "$($Subnet)1"
      }
    }
    Write-Output -InputObject "[$($VMName)]::Renaming OS to `"$($GuestOSName)`""
    Rename-Computer -NewName $GuestOSName
    Write-Output -InputObject "[$($VMName)]::Configuring WSMAN Trusted hosts"
    Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value "*.$($domainName)" -Force | Out-Null
    Set-Item WSMan:\localhost\client\trustedhosts "$($Subnet)*" -Force -concatenate | Out-Null
    Enable-WSManCredSSP -Role Client -DelegateComputer "*.$($domainName)" -Force | Out-Null
  } -ArgumentList $IPNumber, $GuestOSName, $VMName, $domainName, $Subnet

  Restart-DemoVM $VMName
    
  Wait-PSDirect $VMName -cred $localCred
}


function Invoke-NodeStorageBuild 
{
  param
  (
    [string]$VMName, 
    [string]$GuestOSName
  )

  New-DemoVM $VMName $GuestOSName
  Clear-File "$($VMPath)\$($GuestOSName) - Data 1.vhdx"
  Clear-File "$($VMPath)\$($GuestOSName) - Data 2.vhdx"
  Get-VM $VMName | Stop-VM 
  Add-VMNetworkAdapter -VMName $VMName -SwitchName $virtualSwitchName
  New-VHD -Path "$($VMPath)\$($GuestOSName) - Data 1.vhdx" -Dynamic -SizeBytes 200GB 
  Add-VMHardDiskDrive -VMName $VMName -Path "$($VMPath)\$($GuestOSName) - Data 1.vhdx" -ControllerType SCSI
  New-VHD -Path "$($VMPath)\$($GuestOSName) - Data 2.vhdx" -Dynamic -SizeBytes 200GB
  Add-VMHardDiskDrive -VMName $VMName -Path "$($VMPath)\$($GuestOSName) - Data 2.vhdx" -ControllerType SCSI
  Set-VMProcessor -VMName $VMName -Count 2 -ExposeVirtualizationExtensions $True
  Add-VMNetworkAdapter -VMName $VMName -SwitchName $virtualSwitchName
  Add-VMNetworkAdapter -VMName $VMName -SwitchName $virtualSwitchName
  Add-VMNetworkAdapter -VMName $VMName -SwitchName $virtualSwitchName
  Get-VMNetworkAdapter -VMName $VMName | Set-VMNetworkAdapter -AllowTeaming On
  Get-VMNetworkAdapter -VMName $VMName | Set-VMNetworkAdapter -MacAddressSpoofing on
  Start-VM $VMName
  Wait-PSDirect $VMName -cred $localCred

  Invoke-Command -VMName $VMName -Credential $localCred {
    param($VMName, $domainCred, $domainName)
    Write-Output -InputObject "[$($VMName)]:: Installing Clustering"
    $null = Install-WindowsFeature -Name File-Services, Failover-Clustering, Hyper-V -IncludeManagementTools
    Write-Output -InputObject "[$($VMName)]:: Joining domain as `"$($env:computername)`""
    
    while (!(Test-Connection -ComputerName $domainName -BufferSize 16 -Count 1 -Quiet -ea SilentlyContinue)) 
    {
      Start-Sleep -Seconds 1
    }
    
    do 
    {
      Add-Computer -DomainName $domainName -Credential $domainCred -ea SilentlyContinue
    }
    until ($?)
  } -ArgumentList $VMName, $domainCred, $domainName

  Wait-PSDirect $VMName -cred $domainCred

  Invoke-Command -VMName $VMName -Credential $domainCred {
    Rename-NetAdapter -Name 'Ethernet' -NewName 'LOM-P0'
    Rename-NetAdapter -Name 'Ethernet 2' -NewName 'LOM-P1'
    Rename-NetAdapter -Name 'Ethernet 3' -NewName 'Riser-P0'
    Get-NetAdapter -Name 'Ethernet 5' | Rename-NetAdapter -NewName 'Riser-P1'
    New-NetLbfoTeam -Name HyperVTeam -TeamMembers 'LOM-P0' -verbose -confirm:$false
    Add-NetLbfoTeamMember 'LOM-P1' -team HyperVTeam -confirm:$false
    New-NetLbfoTeam -Name StorageTeam -TeamMembers 'Riser-P0' -verbose -confirm:$false
    Add-NetLbfoTeamMember 'Riser-P1' -team StorageTeam -confirm:$false
  }

  Restart-DemoVM $VMName
  Wait-PSDirect $VMName -cred $domainCred

  Test-Connection -ComputerName localhost -Count 20

  Invoke-Command -VMName $VMName -Credential $domainCred {
    New-VMSwitch -Name 'VSW01' -NetAdapterName 'HyperVTeam' -AllowManagementOS $false
    Add-VMNetworkAdapter -ManagementOS -Name ClusterCSV-VLAN204 -Switchname VSW01 -verbose
    Add-VMNetworkAdapter -ManagementOS -Name LM-VLAN203 -Switchname VSW01 -verbose
    Add-VMNetworkAdapter -ManagementOS -Name Servers-VLAN201 -Switchname VSW01 -verbose
    Add-VMNetworkAdapter -ManagementOS -Name MGMT-VLAN200 -Switchname VSW01 -verbose
  }
}


#endregion

#region Variable Init
$BaseVHDPath = "$($WorkingDir)\BaseVHDs"
$VMPath = "$($WorkingDir)\VMs"

$localCred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList 'Administrator', (ConvertTo-SecureString -String $adminPassword -AsPlainText -Force)

$domainCred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "$($domainName)\Administrator", (ConvertTo-SecureString -String $domainAdminPassword -AsPlainText -Force)

$ServerISO = 'c:\ClusterStorage\Volume1\DCBuild\SW_DVD9_Win_Svr_STD_Core_and_DataCtr_Core_2016_64Bit_English_-2_MLF_X21-22843 (1).iso'

$WindowsKey = 'INSERTYOURPRODUCTKEYHERE'

$unattendSource = [xml]@"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <servicing></servicing>
    <settings pass="specialize">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <ComputerName>*</ComputerName>
            <ProductKey>INSERTYOURPRODUCTKEYHERE</ProductKey> 
            <RegisteredOrganization>Organization</RegisteredOrganization>
            <RegisteredOwner>Owner</RegisteredOwner>
            <TimeZone>TZ</TimeZone>
        </component>
    </settings>
    <settings pass="oobeSystem">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <OOBE>
                <HideEULAPage>true</HideEULAPage>
                <HideLocalAccountScreen>true</HideLocalAccountScreen>
                <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
                <NetworkLocation>Work</NetworkLocation>
                <ProtectYourPC>1</ProtectYourPC>
            </OOBE>
            <UserAccounts>
                <AdministratorPassword>
                    <Value>password</Value>
                    <PlainText>True</PlainText>
                </AdministratorPassword>
            </UserAccounts>
        </component>
        <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <InputLocale>en-us</InputLocale>
            <SystemLocale>en-us</SystemLocale>
            <UILanguage>en-us</UILanguage>
            <UILanguageFallback>en-us</UILanguageFallback>
            <UserLocale>en-us</UserLocale>
        </component>
    </settings>
</unattend>
"@
#endregion

Write-Log 'Host' 'Getting started...'

Confirm-Path $BaseVHDPath
Confirm-Path $VMPath
Write-Log 'Host' 'Building Base Images'

if (!(Test-Path -Path "$($BaseVHDPath)\VMServerBase.vhdx")) 
{
  . Initialize-BaseImage
}

if ((Get-VMSwitch | Where-Object -Property name -EQ -Value $virtualSwitchName) -eq $null)
{
  New-VMSwitch -Name $virtualSwitchName -SwitchType Private
}

Invoke-DemoVMPrep 'DC1' 'DC1' -FullServer
Invoke-DemoVMPrep 'DC2' 'DC2'-FullServer
Invoke-DemoVMPrep 'DHCP1' 'DHCP1'-FullServer
Invoke-DemoVMPrep 'MGMT1' 'MGMT1' -FullServer

$VMName = 'DC1'
$GuestOSName = 'DC1'
$IPNumber = '1'

New-DemoVM $VMName $GuestOSName $IPNumber

Invoke-Command -VMName $VMName -Credential $localCred {
  param($VMName, $domainName, $domainAdminPassword)

  Write-Output -InputObject "[$($VMName)]:: Installing AD"
  $null = Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
  Write-Output -InputObject "[$($VMName)]:: Enabling Active Directory and promoting to domain controller"
  Install-ADDSForest -DomainName $domainName -InstallDNS -NoDNSonNetwork -NoRebootOnCompletion -SafeModeAdministratorPassword (ConvertTo-SecureString -String $domainAdminPassword -AsPlainText -Force) -confirm:$false
} -ArgumentList $VMName, $domainName, $domainAdminPassword

Restart-DemoVM $VMName 

$VMName = 'DHCP1'
$GuestOSName = 'DHCP1'
$IPNumber = '3'

New-DemoVM $VMName $GuestOSName $IPNumber

Invoke-Command -VMName $VMName -Credential $localCred {
  param($VMName, $domainCred, $domainName)
  Write-Output -InputObject "[$($VMName)]:: Installing DHCP"
  $null = Install-WindowsFeature DHCP -IncludeManagementTools
  Write-Output -InputObject "[$($VMName)]:: Joining domain as `"$($env:computername)`""
  
  while (!(Test-Connection -ComputerName $domainName -BufferSize 16 -Count 1 -Quiet -ea SilentlyContinue)) 
  {
    Start-Sleep -Seconds 1
  }
  
  do 
  {
    Add-Computer -DomainName $domainName -Credential $domainCred -ea SilentlyContinue
  }
  until ($?)
} -ArgumentList $VMName, $domainCred, $domainName

Restart-DemoVM $VMName
Wait-PSDirect $VMName -cred $domainCred

Invoke-Command -VMName $VMName -Credential $domainCred {
  param($VMName, $domainName, $Subnet, $IPNumber)

  Write-Output -InputObject "[$($VMName)]:: Waiting for name resolution"

  while ((Test-NetConnection -ComputerName $domainName).PingSucceeded -eq $false) 
  {
    Start-Sleep -Seconds 1
  }

  Write-Output -InputObject "[$($VMName)]:: Configuring DHCP1"    
  Set-DhcpServerv4Binding -BindingState $True -InterfaceAlias Ethernet
  Add-DhcpServerv4Scope -Name 'IPv4 Network' -StartRange "$($Subnet)10" -EndRange "$($Subnet)200" -SubnetMask 255.255.255.0
  Set-DhcpServerv4OptionValue -OptionId 6 -value "$($Subnet)1"
  Add-DhcpServerInDC -DnsName "$($env:computername).$($domainName)"
  
  foreach($i in 1..99) 
  {
    $mac = '00-b5-5d-fe-f6-' + ($i % 100).ToString('00')
    $ip = $Subnet + '1' + ($i % 100).ToString('00')
    $desc = 'Container ' + $i.ToString()
    $scopeID = $Subnet + '0'
    Add-DhcpServerv4Reservation -IPAddress $ip -ClientId $mac -Description $desc -ScopeId $scopeID
  }
} -ArgumentList $VMName, $domainName, $Subnet, $IPNumber

Restart-DemoVM $VMName

$VMName = 'DC2'
$GuestOSName = 'DC2'
$IPNumber = '2'

New-DemoVM $VMName $GuestOSName $IPNumber

Invoke-Command -VMName $VMName -Credential $localCred {
  param($VMName, $domainCred, $domainName)
  Write-Output -InputObject "[$($VMName)]:: Installing AD"
  $null = Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
  Write-Output -InputObject "[$($VMName)]:: Joining domain as `"$($env:computername)`""
  while (!(Test-Connection -ComputerName $domainName -BufferSize 16 -Count 1 -Quiet -ea SilentlyContinue)) 
  {
    Start-Sleep -Seconds 1
  }
  
  do 
  {
    Add-Computer -DomainName $domainName -Credential $domainCred -ea SilentlyContinue
  }
  until ($?)
} -ArgumentList $VMName, $domainCred, $domainName

Restart-DemoVM $VMName
Wait-PSDirect $VMName -cred $domainCred

Invoke-Command -VMName $VMName -Credential $domainCred {
  param($VMName, $domainName, $domainAdminPassword)

  Write-Output -InputObject "[$($VMName)]:: Waiting for name resolution"

  while ((Test-NetConnection -ComputerName $domainName).PingSucceeded -eq $false) 
  {
    Start-Sleep -Seconds 1
  }

  Write-Output -InputObject "[$($VMName)]:: Enabling Active Directory and promoting to domain controller"
    
  Install-ADDSDomainController -DomainName $domainName -InstallDNS -NoRebootOnCompletion -SafeModeAdministratorPassword (ConvertTo-SecureString -String $domainAdminPassword -AsPlainText -Force) -confirm:$false
} -ArgumentList $VMName, $domainName, $domainAdminPassword

Restart-DemoVM $VMName

$VMName = 'DC1'
$GuestOSName = 'DC1'
$IPNumber = '1'

Wait-PSDirect $VMName -cred $domainCred

Invoke-Command -VMName $VMName -Credential $domainCred {
  param($VMName, $password)

  Write-Output -InputObject "[$($VMName)]:: Creating user account for Dave"
  do 
  {
    Start-Sleep -Seconds 5
    New-ADUser -Name 'Dave' -SamAccountName  'Dave' -DisplayName 'Dave' -AccountPassword (ConvertTo-SecureString -String $password -AsPlainText -Force) -ChangePasswordAtLogon $false -Enabled $True -ea 0
  }
  until ($?)
  Add-ADGroupMember -Identity 'Domain Admins' -Members 'Dave'
} -ArgumentList $VMName, $domainAdminPassword

$VMName = 'MGMT1'
$GuestOSName = 'MGMT1'

New-DemoVM $VMName $GuestOSName

Invoke-Command -VMName $VMName -Credential $localCred {
  param($VMName, $domainCred, $domainName)
  Write-Output -InputObject "[$($VMName)]:: Management tools"
  $null = Install-WindowsFeature RSAT-Clustering, RSAT-Hyper-V-Tools
  Write-Output -InputObject "[$($VMName)]:: Joining domain as `"$($env:computername)`""
  while (!(Test-Connection -ComputerName $domainName -BufferSize 16 -Count 1 -Quiet -ea SilentlyContinue)) 
  {
    Start-Sleep -Seconds 1
  }
  
  do 
  {
    Add-Computer -DomainName $domainName -Credential $domainCred -ea SilentlyContinue
  }
  until ($?)
} -ArgumentList $VMName, $domainCred, $domainName

Restart-DemoVM $VMName

1..4 | ForEach-Object -Process {
  Invoke-DemoVMPrep "S2D$_" "S2D$_" -FullServer
}

Wait-PSDirect 'S2D4' -cred $localCred

$VMName = 'S2D1'
$GuestOSName = 'S2D1'

1..4 | ForEach-Object -Process {
  Invoke-NodeStorageBuild "S2D$_" "S2D$_"
}

Wait-PSDirect 'S2D3' -cred $domainCred

Invoke-Command -VMName 'MGMT1' -Credential $domainCred {
  param ($domainName)
  do 
  {
    New-Cluster -Name S2DCluster -Node S2D1, S2D2, S2D3 -NoStorage
  }
  until ($?)
  
  while (!(Test-Connection -ComputerName "S2DCluster.$($domainName)" -BufferSize 16 -Count 1 -Quiet -ea SilentlyContinue)) 
  {
    ipconfig.exe /flushdns
    Start-Sleep -Seconds 1
  }
} -ArgumentList $domainName

Invoke-Command -VMName 'S2D1' -Credential $domainCred {
  param ($domainName)
  Enable-ClusterStorageSpacesDirect -PoolFriendlyName S2DPool -confirm:$false

  # This will match the configuration that was done in the book
  New-Volume -StoragePoolFriendlyName S2DPool -FriendlyName Mirror-2Way -FileSystem CSVFS_REFS -Size 200GB -PhysicalDiskRedundancy 1 
  New-Volume -StoragePoolFriendlyName S2DPool -FriendlyName Mirror-3Way -FileSystem CSVFS_REFS -Size 200GB -PhysicalDiskRedundancy 2
} -ArgumentList $domainName

Write-Log 'Done' 'Done!'
