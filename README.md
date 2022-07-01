# AZ80xLab
playground environment for AZ80x

# Description
You can use this set of scripts to deploy a lab environment for AZ800/AZ-801 powered by AutomatedLab (https://automatedlab.org/en/latest/). 
## Environment
### DC1
Domain Controller, DNS, RRAS service offering internet connectivity to the rest of the machines
Configured Features: several user in the "Resources" OU, several sample and Security Baseline GPOs (not linked), central ADMX store, authentication silo/policy
### ADM1
Admin server, the only one with a GUI. 
Configured Roles/Features: RSAT, Windows Admin Center with all available extensions, PKI, DHCP
Prepared roles for further confguration: IPAM, System Insights, Storage Migration Services, Storage Replica, File Services
### SRV1
iSCSI target offering three disks to the failover cluster nodes
Prepared roles for further confguration: Data Dedeuplication, Storage Replica
### CL1-01/CL1-02
Cluster nodes forming a failover cluster (CLUSTER1), using 3 iSCSI disks offered from SRV1.
### S2D1-01/S2D1-01
Storage Spaces Direct Cluster nodes with Hyper-V role forming cluster S2D1. 
Hyper-V is configured and a VM is pre-created on the Cluster Shared Volume. To use the VM, start it to complete setup, eject the DVD and import the machine as a cluster role in Hyper-V, e.g. to demo Live Migration.

# Azure preparation instructions
- deploy the Bicep file to a resource group of your choice, example in PowerShell:
```PowerShell
Install-Module Az
Connect-AzAccount
New-AzResourceGroup -Name "AZ80xLab" -Location westeurope
New-AzResourceGroupDeployment -Name "AZ80xLab" -ResourceGroupName "AZ80xLab" -TemplateFile .\HyperV.bicep
```
This willl set up a virtual machine in Azure capable of running Hyper-V, downlaod the AutomatedLab module and prepare it with a Windows Sevrer 2022 Evaluation image. It will also clone this repository into C:\git\AZ80xLab. 

After deployment, connect to the VM, launch PowerShell as administrator and launch C:\git\AZ80xLab\AZ80x.ps1. Note: while creating the external switch in Hyper-V, you will lose the RDP connection and need to reconnect. Follw Lab setup instructions (below) from this point

# Local preparation instructions
- Run PowerShell as an admin
- install the AutomatedLab module (install-module AutomatedLab)
- download ISO files as required and store them in C:\Labsources\ISO. To get an Evaluation version of Windows Sevrer 2022, run 
```PowerShell
Start-BitsTransfer -Destination C:\LabSources\ISOs\WindowsServer2022Eval.iso -Source 'https://go.microsoft.com/fwlink/p/?LinkID=2195280&clcid=0x409&culture=en-us&country=US'
```
# Lab setup instructions
After preparation, run AZ80x.ps1. The script will prompt for a user name and password to be used for the environment. You can specify further parameters (TODO: add help), e.g. 
```PowerShell
AZ80x.ps1 -DomainName litware.local -VMPath D:\MyLab -LabName MyLab
```
To entirely remove the lab environment run the following. Replace AZ80x with your own lab name if you specified one.
```PowerShell
Import-Lab AZ80x
Remove-Lab
```
For documentation about AutomatedLab please refer to https://automatedlab.org/en/latest/
