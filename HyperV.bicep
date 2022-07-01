param vmSize string = 'Standard_D8s_v5'
param computerName string = 'AZ80x-HyperV'
param location string = resourceGroup().location
@secure()
param adminUserName string
@secure()
@minLength(12)
param adminPassword string

var postConfigPS1 = '''
Add-WindowsFeature -Name Hyper-V -IncludeAllSubFeature -IncludeManagementTools
Initialize-Disk -Number 1 -PartitionStyle MBR
New-Partition -DiskNumber 1 -UseMaximumSize -DriveLetter E
Format-Volume -DriveLetter E -FileSystem ReFS
Install-PackageProvider -Name Nuget -MinimumVersion 2.8.5.201 -Force
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
Install-Module -Name Pester -SkipPublisherCheck -Force
Install-Module -Name AutomatedLab -AllowClobber -Force
[Environment]::SetEnvironmentVariable('AUTOMATEDLAB_TELEMETRY_OPTIN', 'true', 'Machine')
$env:AUTOMATEDLAB_TELEMETRY_OPTIN = 'true'
Import-Module AutomatedLab -Force
New-LabSourcesFolder -DriveLetter C -Force
Enable-LabHostRemoting -Force
Update-LabSysinternalsTools
# download Windows Server 2022 Evaluation
Start-BitsTransfer -Destination C:\LabSources\ISOs\WindowsServer2022Eval.iso -Source 'https://go.microsoft.com/fwlink/p/?LinkID=2195280&clcid=0x409&culture=en-us&country=US'
Unblock-LabSources
#install git
Install-Module Chocolatey
Install-ChocolateySoftware
Enable-ChocolateyFeature -Name allowGlobalConfirmation
Install-ChocolateyPackage -Name git -Confirm:$false
[Environment]::SetEnvironmentVariable('Path',($Env:Path + ';' + 'C:\Program Files\Git\bin'),'Machine')
[Environment]::SetEnvironmentVariable('Path',($Env:Path + ';' + 'C:\Program Files\Git\bin'),'Process')
[Environment]::SetEnvironmentVariable('GIT_REDIRECT_STDERR','2>&1' ,'Machine')
[Environment]::SetEnvironmentVariable('GIT_REDIRECT_STDERR','2>&1' ,'Process')
New-Item -Path C:\git -ItemType Directory -Force
& $env:ProgramFiles\git\bin\git.exe clone https://github.com/jkulbe-msft/AZ80xLab "C:\git\AZ80xLab"
Restart-Computer
'''

resource windowsVM 'Microsoft.Compute/virtualMachines@2020-12-01' = {
  name: computerName
  location: location
  properties: {
    hardwareProfile: {
      vmSize: vmSize
    }
    osProfile: {
      computerName: computerName
      adminUsername: adminUserName
      adminPassword: adminPassword
    }
    storageProfile: {
      imageReference: {
        publisher: 'MicrosoftWindowsServer'
        offer: 'WindowsServer'
        sku: '2022-datacenter-azure-edition'
        version: 'latest'
      }
      osDisk: {
        name: '${computerName}-OSDisk'
        caching: 'ReadWrite'
        createOption: 'FromImage'
        managedDisk: {
          storageAccountType: 'StandardSSD_LRS'
        }
      }
      dataDisks: [
        {
          name: '${computerName}-DataDisk'
          lun:0
          createOption: 'Empty'
          diskSizeGB: 512
          caching: 'ReadWrite'
          managedDisk: {
            storageAccountType: 'StandardSSD_LRS'
          }
        }
      ]
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: networkInterface.id
        }
      ]
    }
    diagnosticsProfile: {
      bootDiagnostics: {
        enabled: true
        storageUri:  diagstorageaccount.properties.primaryEndpoints.blob
      }
    }
  }
}

resource diagstorageaccount 'Microsoft.Storage/storageAccounts@2021-02-01' = {
  name: 'diag${uniqueString(resourceGroup().id)}'
  location: location
  kind: 'StorageV2'
  sku: {
    name: 'Standard_LRS'
  }
  
}

resource networkInterface 'Microsoft.Network/networkInterfaces@2020-11-01' = {
  name: '${computerName}-NIC'
  location: location
  properties: {
    ipConfigurations: [
      {
        name: '${computerName}-IP'
        properties: {
          privateIPAllocationMethod: 'Dynamic'
          publicIPAddress: {
            id: publicIPAddress.id
          }
          subnet: {
            id: resourceId('Microsoft.Network/virtualNetworks/subnets', virtualNetwork.name, 'Subnet-1')
          }
        }
      }
    ]
    networkSecurityGroup: {
      id: securityGroup.id
    }
  }
}

resource publicIPAddress 'Microsoft.Network/publicIPAddresses@2019-11-01' = {
  name: '${computerName}-PIP'
  location: location
  properties: {
    publicIPAllocationMethod: 'Dynamic'
    dnsSettings: {
      domainNameLabel: toLower('${computerName}-${uniqueString(resourceGroup().id, computerName)}')
    }
  }
}

resource virtualNetwork 'Microsoft.Network/virtualNetworks@2019-11-01' = {
  name: '${computerName}-VNet'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.0.0.0/16'
      ]
    }
    subnets: [
      {
        name: 'Subnet-1'
        properties: {
          addressPrefix: '10.0.0.0/24'
        }
      }
    ]
  }
}

resource securityGroup 'Microsoft.Network/networkSecurityGroups@2021-02-01' = {
  name: '${computerName}-NSG'
  location: location
  properties: {
    securityRules: [
      {
        name: 'default-allow-3389'
        properties: {
          priority: 1000
          access: 'Allow'
          direction: 'Inbound'
          destinationPortRange: '3389'
          protocol: 'Tcp'
          sourcePortRange: '*'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
        }
      }
    ]
  }
}

resource postConfigScript 'Microsoft.Compute/virtualMachines/runCommands@2022-03-01' = {
  name: '${computerName}-RunCommand'
  parent: windowsVM
  location: location
  properties: {
    asyncExecution: false
    timeoutInSeconds: 1200
    source: {
      script: postConfigPS1
    }
  }
}

output hostname string = publicIPAddress.properties.dnsSettings.fqdn
