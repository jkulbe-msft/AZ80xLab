#Requires -RunAsAdministrator

param(

$labName = 'AZ80x',

$vmpath = "D:\$labname",

$domainName = 'contoso.com',

$osName = 'Windows Server 2022 Datacenter Evaluation',

$osNameWithDesktop = 'Windows Server 2022 Datacenter Evaluation (Desktop Experience)',

$cred = (Get-Credential -Message 'Enter user name and password for lab machines')

)

$iso = (Get-LabAvailableOperatingSystem | where OperatingSystemName -like $osNameWithDesktop).IsoPath

$username = $cred.UserName
$passwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred.Password))

If (!(Get-VMSwitch -Name 'NATSwitch' -ErrorAction SilentlyContinue))
{
    New-VMSwitch -SwitchName 'NATSwitch' -SwitchType Internal
    New-NetIPAddress -IPAddress 192.168.51.1 -PrefixLength 24 -InterfaceAlias 'vEthernet (NATSwitch)'
    New-NetNAT -Name 'NATNetwork' -InternalIPInterfaceAddressPrefix 192.168.51.0/24
}

If (!(Get-VMSwitch -Name 'External' -ErrorAction SilentlyContinue))
{
    New-VMSwitch -SwitchName 'External' -NetAdapterName (Get-NetRoute -DestinationPrefix 0.0.0.0/0).InterfaceAlias -AllowManagementOS:$true
}

New-LabDefinition -Name $labname -DefaultVirtualizationEngine HyperV -VmPath $vmpath

Add-LabVirtualNetworkDefinition -Name $labname -AddressSpace '192.168.50.0/24'
#Add-LabVirtualNetworkDefinition -Name 'External' -HyperVProperties @{ SwitchType = 'External'; AdapterName = ((Get-NetRoute -DestinationPrefix 0.0.0.0/0).InterfaceAlias) }
Add-LabVirtualNetworkDefinition -Name 'External'

$netAdapter = @()
$netAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $labname
$netAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch 'External' -UseDhcp
#$netAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch 'NATSwitch'  -Ipv4Address 192.168.51.2 -Ipv4Gateway 192.168.51.1 

#defining default parameter values, as these ones are the same for all the machines
$PSDefaultParameterValues = @{
    'Add-LabMachineDefinition:DomainName' = $domainName
    'Add-LabMachineDefinition:Memory' = 2GB
    #'Add-LabMachineDefinition:MinMemory' = 1GB
    #'Add-LabMachineDefinition:MaxMemory' = 8GB
    'Add-LabMachineDefinition:EnableWindowsFirewall' = $true
    'Add-LabMachineDefinition:Processors' = 2
    'Add-LabMachineDefinition:OperatingSystem' = $osName
}

Add-LabDomainDefinition -Name $domainName -AdminUser $username -AdminPassword $passwd
Set-Labinstallationcredential -Username $username -Password $passwd

# Domain Controller
Add-LabMachineDefinition -Name 'DC1' -Roles RootDC,Routing -NetworkAdapter $netAdapter -MinMemory 512MB -MaxMemory 4GB

# Admin server
Add-LabDiskDefinition -Name 'ADM1-Data' -DiskSizeInGb 10 -Label 'Data' -DriveLetter S
Add-LabDiskDefinition -Name 'ADM1-Logs' -DiskSizeInGb 10 -Label 'Logs' -DriveLetter L
Add-LabMachineDefinition -Name 'ADM1' -Roles CARoot,WindowsAdminCenter,FileServer -IsDomainJoined -Network $labname -OperatingSystem $osNameWithDesktop -DiskName 'ADM1-Data','ADM1-Logs' -MinMemory 1GB -MaxMemory 8GB

# file server
Add-LabDiskDefinition -Name 'SRV1-Data' -DiskSizeInGb 10 -Label 'Data' -DriveLetter S
Add-LabDiskDefinition -Name 'SRV1-Logs' -DiskSizeInGb 10 -Label 'Logs' -DriveLetter L
Add-LabDiskDefinition -Name 'SRV1-Dedup' -DiskSizeInGb 10 -Label 'Dedup' -DriveLetter D
Add-LabDiskDefinition -Name 'SRV1-iSCSI' -DiskSizeInGb 40 -Label 'iSCSI' -DriveLetter I
Add-LabMachineDefinition -Name 'SRV1' -Roles FileServer -IsDomainJoined -Network $labname -DiskName 'SRV1-Data','SRV1-Logs','SRV1-Dedup','SRV1-iSCSI' -MinMemory 512MB -MaxMemory 4GB


# S2D cluster
1..3 | Foreach-Object {
    Add-LabDiskDefinition -Name "S2D-Disk1-$($_)" -DiskSizeInGb 25 -SkipInitialize
    Add-LabDiskDefinition -Name "S2D-Disk2-$($_)" -DiskSizeInGb 25 -SkipInitialize
}
Add-LabMachineDefinition -Name 'S2D1-01' -Roles HyperV -IsDomainJoined -Network $labname -DiskName 'S2D-Disk1-1','S2D-Disk1-2','S2D-Disk1-3' -Memory 4GB
Add-LabMachineDefinition -Name 'S2D1-02' -Roles HyperV -IsDomainJoined -Network $labname -DiskName 'S2D-Disk2-1','S2D-Disk2-2','S2D-Disk2-3' -Memory 4GB

Add-LabMachineDefinition -Name 'CL1-01' -Network $labname -IsDomainJoined -MinMemory 512MB -MaxMemory 4GB
Add-LabMachineDefinition -Name 'CL1-02' -Network $labname -IsDomainJoined -MinMemory 512MB -MaxMemory 4GB

Install-Lab -DelayBetweenComputers 180

# Features
$dcjob = Install-LabWindowsFeature -FeatureName RSAT -ComputerName 'DC1' -IncludeAllSubFeature -IncludeManagementTools
$admjob = Install-LabWindowsFeature -FeatureName RSAT,DHCP,File-Services,SMS,Storage-Replica,System-Insights,Migration,IPAM -ComputerName 'ADM1' -IncludeAllSubFeature -AsJob -PassThru
$cljob = Install-LabWindowsFeature -FeatureName File-Services,Failover-Clustering -IncludeManagementTools -ComputerName 'S2D1-01','S2D1-02','CL1-01','CL1-02' -IncludeAllSubFeature -AsJob -PassThru
$srvjob = Install-LabWindowsFeature -FeatureName DHCP,FS-Data-Deduplication,FS-iSCSITarget-Server,Storage-Replica -IncludeManagementTools -ComputerName 'SRV1' -IncludeAllSubFeature -AsJob -PassThru

# Install and update WAC extensions
$wacjob = Invoke-LabCommand -ActivityName "WAC Update" -ComputerName ADM1 -AsJob -PassThru -ScriptBlock { 
    Import-Module "$env:ProgramFiles\windows admin center\PowerShell\Modules\ExtensionTools"
    Get-Extension "https://adm1" | ? status -eq Available | foreach {Install-Extension "https://adm1" $_.id}
    Get-Extension "https://adm1" | ? islatestVersion -ne $true | foreach {Update-Extension "https://adm1" $_.id}
 }

Wait-LWLabJob -Job $dcjob -ProgressIndicator 10 -NoDisplay -PassThru
Wait-LWLabJob -Job $admjob -ProgressIndicator 10 -NoDisplay -PassThru
Wait-LWLabJob -Job $cljob -ProgressIndicator 10 -NoDisplay -PassThru
Wait-LWLabJob -Job $srvjob -ProgressIndicator 10 -NoDisplay -PassThru
Wait-LWLabJob -Job $wacjob -ProgressIndicator 10 -NoDisplay -PassThru

Get-LabVM | ? Name -ne 'dc1' | Restart-LabVM -Wait

# AD setup
Invoke-LabCommand -ActivityName "OUs part 1" -ComputerName DC1 -ScriptBlock { New-ADOrganizationalUnit -Name "Resources" -Path "DC=$(($using:domainName -split "\.")[-2]),DC=$(($using:domainName -split "\.")[-1])" } -Variable $domainName
Invoke-LabCommand -ActivityName "OUs part 2" -ComputerName DC1 -ScriptBlock { "Users","Computers","Groups" | Foreach-Object { New-ADOrganizationalUnit -Name $_ -Path "OU=Resources,DC=$(($using:domainName -split "\.")[-2]),DC=$(($using:domainName -split "\.")[-1])"} } -Variable $domainName
Invoke-LabCommand -ActivityName "Users" -ComputerName DC1 -ScriptBlock { "User1","User2","DelegatedIpamUser","AdminInSilo" | Foreach-Object { New-ADUser -Name $_ -AccountPassword ($using:passwd | ConvertTo-SecureString -AsPlainText -Force) -PasswordNeverExpires $true -Enabled $true -Path "OU=Users,OU=Resources,DC=$(($using:domainName -split "\.")[-2]),DC=$(($using:domainName -split "\.")[-1])"} } -Variable $domainName,$passwd
Invoke-LabCommand -ActivityName "second admin permissions" -ComputerName DC1 -ScriptBlock { Add-ADGroupMember -Identity "Domain Admins" -Members 'AdminInSilo'  }
Copy-LabFileItem -Path $PSScriptRoot\PolicyDefinitions -ComputerName DC1 -DestinationFolderPath C:\Windows\Sysvol\domain\Policies
Copy-LabFileItem -Path $PSScriptRoot\SecurityBaselineGPO -ComputerName DC1 -DestinationFolderPath C:\Lab
Invoke-LabCommand -ActivityName "GPO import" -ComputerName DC1 -ScriptBlock { C:\Lab\SecurityBaselineGPO\import-baselinegpo.ps1 }
Invoke-LabCommand -ActivityName "resgister AD Schema extension" -ComputerName ADM1 -ScriptBlock { regsvr32 /s schmmgmt.dll }
# Authentication Silo
Invoke-LabCommand -ActivityName "Authentication Silo" -ComputerName DC1 -ScriptBlock {  
    New-ADAuthenticationPolicy -Name "Reduced_Admin_TGT" `
                               -Description "Authentication policy to set 2 hour Ticket Granting Ticket for administrators" `
                               -UserTGTLifetimeMins 120 `
                               -ProtectedFromAccidentalDeletion $True

    Set-ADAuthenticationPolicy -Identity "Reduced_Admin_TGT" `
                               -UserAllowedToAuthenticateFrom "O:SYG:SYD:(XA;OICI;CR;;;WD;(@USER.ad://ext/AuthenticationSilo == `"Controlled_Admin_Logon`"))"

    New-ADAuthenticationPolicySilo -Name "Controlled_Admin_Logon" `
                                   -Description "Authentication policy silo to control the scope of logon for administrators" `
                                   -UserAuthenticationPolicy "Reduced_Admin_TGT" `
                                   -ComputerAuthenticationPolicy "Reduced_Admin_TGT" `
                                   -ServiceAuthenticationPolicy "Reduced_Admin_TGT" `
                                   -ProtectedFromAccidentalDeletion $True `
                                   -Enforce

    Get-ADDomainController -Filter {IsReadOnly -eq $False} |
    ForEach-Object {Grant-ADAuthenticationPolicySiloAccess -Identity "Controlled_Admin_Logon" -Account $_.ComputerObjectDN}
    Get-ADGroupMember -Identity "Domain Admins" |
    ForEach-Object {Grant-ADAuthenticationPolicySiloAccess -Identity "Controlled_Admin_Logon" -Account $_.DistinguishedName}

    # (Get-ADAuthenticationPolicySilo -Identity "Controlled_Admin_Logon").Members

    #Get-ADGroupMember -Identity "Domain Admins" |
    Get-ADUser -Identity "AdminInSilo" |
    ForEach-Object {Grant-ADAuthenticationPolicySiloAccess -Identity "Controlled_Admin_Logon" -Account $_.DistinguishedName}

    (Get-ADAuthenticationPolicySilo -Identity "Controlled_Admin_Logon").Members
    (Get-ADAuthenticationPolicySilo -Identity "Controlled_Admin_Logon").Members |
    Get-ADObject -Properties msDS-AuthNPolicySiloMembersBL

    Get-ADComputer -LDAPFilter "(&(&(&(samAccountType=805306369)(useraccountcontrol:1.2.840.113556.1.4.803:=8192))))" |
    Set-ADAccountAuthenticationPolicySilo -AuthenticationPolicySilo "Controlled_Admin_Logon"

    # Get-ADGroupMember -Identity "Domain Admins" |
    Get-ADUser -Identity "AdminInSilo" |
    Set-ADAccountAuthenticationPolicySilo -AuthenticationPolicySilo "Controlled_Admin_Logon"

    #(Get-ADAuthenticationPolicySilo -Identity "Controlled_Admin_Logon").Members |
    #Get-ADObject -Properties msDS-AuthNPolicySiloMembersBL, msDS-AssignedAuthNPolicySilo
    }

# DHCP
Invoke-LabCommand -ActivityName "configure DHCP server" -ComputerName 'ADM1' -ScriptBlock {
    Add-DhcpServerInDC
    Add-DhcpServerv4Scope -Name "LabScope" -StartRange 192.168.50.100 -EndRange 192.168.50.200 -SubnetMask 255.255.255.0
    Set-DhcpServerv4OptionValue -DnsDomain $using:domainname -DnsServer 192.168.50.3
    Set-DhcpServerv4OptionValue -ScopeId 192.168.50.100 -Router 192.168.50.3
} -Variable $domainName


# SMB share
# create SMB share on data disk on SRV1
Invoke-LabCommand -ActivityName "create SMB shares" -ComputerName 'SRV1' -ScriptBlock {
    New-Item -Path S:\Share -ItemType Directory -Force
    icacls S:\Share /grant 'Domain Computers:(OI)(CI)F' 
    New-SmbShare -Path S:\Share -FullAccess 'Everyone' -Name Share
}
# add file share witness for S2D cluster quorum
Invoke-LabCommand -ActivityName "create cluster witness share" -ComputerName 'DC1' -ScriptBlock {
    New-Item -Path C:\CLFileShareWitness -ItemType Directory -Force
    icacls C:\CLFileShareWitness /grant 'Domain Computers:(OI)(CI)F' 
    New-SmbShare -Path C:\CLFileShareWitness -FullAccess 'Everyone' -Name CLFileShareWitness
}

# TODO IPAM
# triggers a confirmation prompt while creating the GPOs, haven't found a way around them ("$ConfirmationPreference = "None" and $PSDefaultParameterValues... didn't work for me)
# Invoke-LabCommand -ActivityName "Create IPAM GPOs" -ComputerName DC1 -ScriptBlock { Invoke-IpamGpoProvisioning -GpoPrefixName IPAM -Domain $using:domainName -IpamServerFqdn "adm1.$using:domainname" -DelegatedGpoUser "DelegatedIpamUser" -Force  } -Variable $domainName

# ISCSI 
# create virtual iScsi disks on srv1  
Invoke-LabCommand -ActivityName "iScsi target" -ComputerName SRV1 -ScriptBlock {
    Enable-NetFirewallRule 'MsiScsi-In-TCP','MsiScsi-Out-TCP'
    #Set-Service -ServiceName MSiSCSI -StartupType Automatic
    #Start-Service -ServiceName MSiSCSI
    New-Item -Path I:\ISCSI -ItemType Directory -Force
    New-IscsiVirtualDisk -Path I:\ISCSI\disk1.vhdx -size 10GB
    New-IscsiVirtualDisk -Path I:\ISCSI\disk2.vhdx -size 10GB
    New-IscsiVirtualDisk -Path I:\ISCSI\disk3.vhdx -size 10GB
    
    New-IscsiServerTarget iSCSI-L03 -InitiatorIds "IQN:iqn.1991-05.com.microsoft:cl1-01.$using:domainname","IQN:iqn.1991-05.com.microsoft:cl1-02.$using:domainname"
    
    Add-IscsiVirtualDiskTargetMapping iSCSI-L03 I:\ISCSI\Disk1.VHDX
    Add-IscsiVirtualDiskTargetMapping iSCSI-L03 I:\ISCSI\Disk2.VHDX
    Add-IscsiVirtualDiskTargetMapping iSCSI-L03 I:\ISCSI\Disk3.VHDX

    Restart-Service WinTarget
} -Variable $domainName
# and mount them to CL1-01/-02
Invoke-LabCommand -ActivityName "iScsi initiator" -ComputerName 'CL1-01','CL1-02' -ScriptBlock {
    Set-Service -ServiceName MSiSCSI -StartupType Automatic
    Start-Service -ServiceName MSiSCSI
    Enable-NetFirewallRule 'MsiScsi-In-TCP','MsiScsi-Out-TCP'
    New-iSCSITargetPortal -TargetPortalAddress "SRV1.$using:domainName"
    Connect-iSCSITarget -NodeAddress iqn.1991-05.com.microsoft:srv1-iSCSI-L03-target -IsPersistent $true
} -Variable $domainName
# intialize cluster disks
Invoke-LabCommand -ActivityName "iScsi disk init" -ComputerName 'CL1-01' -ScriptBlock {
    Get-Disk | Where OperationalStatus -eq 'Offline' | Initialize-Disk -PartitionStyle MBR
    New-Partition -DiskNumber 1 -Size 5gb -AssignDriveLetter
    New-Partition -DiskNumber 2 -Size 5gb -AssignDriveLetter
    New-Partition -DiskNumber 3 -Size 5gb -AssignDriveLetter
    Format-Volume -DriveLetter E -FileSystem NTFS
    Format-Volume -DriveLetter F -FileSystem NTFS
    Format-Volume -DriveLetter G -FileSystem NTFS
}

# create failover cluster
Restart-LabVM -ComputerName cl1-01,cl1-02
Invoke-LabCommand -ActivityName "configure failover cluster" -ComputerName 'CL1-01' -ScriptBlock {
    New-Cluster -Name CLUSTER1 -Node cl1-01 -StaticAddress 192.168.50.20
    Add-ClusterNode -Name cl1-02
}
Restart-LabVM -ComputerName cl1-01,cl1-02

# Storage Spaces Direct Cluster
Set-VMProcessor -VMName S2D1-01,S2D1-02 -ExposeVirtualizationExtensions $true
Restart-LabVM -ComputerName S2D1-01,S2D1-02
Invoke-LabCommand -ActivityName "configure S2D cluster" -ComputerName 'S2D1-01' -ScriptBlock {
    New-Cluster -Name S2D1 -Node S2D1-01,S2D1-02 -StaticAddress 192.168.50.30 -NoStorage
    Enable-ClusterStorageSpacesDirect -SkipEligibilityChecks -Confirm:$false
    New-Volume -StoragePoolFriendlyName 'S2D on S2D1' -FriendlyName "CSV" -FileSystem CSVFS_ReFS -UseMaximumSize
}
Restart-LabVM -ComputerName S2D1-01,S2D1-02
Copy-LabFileItem -Path $iso -ComputerName 'S2D1-01' -DestinationFolderPath C:\iso
Invoke-LabCommand -ActivityName "configure S2D cluster" -ComputerName 'S2D1-01' -ScriptBlock {
    New-VM -Name 'ClusteredVM' -MemoryStartupBytes 2GB -NewVHDPath 'C:\ClusterStorage\CSV\ClusteredVM.vhdx' -NewVHDSizeBytes 45GB -Generation 2 -Path 'C:\ClusterStorage\CSV\'
    Add-VMDvdDrive -VMName 'ClusteredVM' -Path "C:\ISO\$(Split-Path $using:iso -Leaf)"
    Get-VM -Name 'ClusteredVM' | Set-VM -ProcessorCount 2
} -Variable $domainName, $iso

Show-LabDeploymentSummary -Detailed