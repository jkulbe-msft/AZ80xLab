# AZ80xLab
playground environment for AZ80x

# Hyper-V Host Virtual Machine with nested VMs.

This template will automate the deployment of a Virtual Machine to be a Hyper-V Host to be used for nested virtualization. Nested Virtual Machines will be able to communicate out to the internet and to other resources on your network.

The setup is completed based on the procedure from the article [Nested VMs in Azure Virtual Networks](https://docs.microsoft.com/virtualization/hyper-v-on-windows/user-guide/nested-virtualization-azure-virtual-network)

This template creates the following resources by default:

+    Virtual Network with four Subnets
+    Virtual Machine to be the Hyper-V Host
+    Public IP Address for remote access to Hyper-V Host
+    Network Security Groups with Default Rules
+    Route Table for Azure Virtual Machines to communicate with nested Virtual Machines
+    DSC Extension to install Windows Features
+    Custom Script Extension to configure Hyper-V Server

Click the button below to deploy from the portal:

[![Deploy To Azure](https://raw.githubusercontent.com/jkulbe-msft/AZ80xLab/main/images/deploytoazure.svg?sanitize=true)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fjkulbe-msft%2FAZ80xLab%2Fmain%2Fazuredeploy.json)
[![Visualize](https://raw.githubusercontent.com/jkulbe-msft/AZ80xLab/main/images/visualizebutton.svg?sanitize=true)](http://armviz.io/#/?load=https%3A%2F%2Fraw.githubusercontent.com%2Fjkulbe-msft%2FAZ80xLab%2Fmain%2Fazuredeploy.json)

Deploy Arc lab to Azure:
[![Deploy Arc lab to Azure](https://raw.githubusercontent.com/jkulbe-msft/AZ80xLab/main/images/deploytoazure.svg?sanitize=true)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fjkulbe-msft%2FAZ80xLab%2Fmain%2Fazuredeploy_arc.json)


# Description
You can use this set of scripts to deploy a lab environment for AZ-800/AZ-801 powered by AutomatedLab (https://automatedlab.org/en/latest/). 
The user name and password for the Hyper-V machines is Administrator/Somepass1
## Environment
### DC1
Domain Controller, DNS, RRAS service offering internet connectivity to the rest of the machines
Configured Features: several users in the "Resources" OU, several sample and Security Baseline GPOs (not linked), central ADMX store, authentication silo/policy
### ADM1
Admin server, the only one with a GUI. 
Configured Roles/Features: RSAT, Windows Admin Center with all available extensions, PKI, DHCP
Prepared roles for further confguration: IPAM, System Insights, Storage Migration Services, Storage Replica, File Services
### SRV1
iSCSI target offering three disks to the failover cluster nodes
Prepared roles for further confguration: Data Deduplication, Storage Replica
### CL1-01/CL1-02
Cluster nodes forming a failover cluster (CLUSTER1), using 3 iSCSI disks offered from SRV1.
### S2D1-01/S2D1-01
Storage Spaces Direct Cluster nodes with Hyper-V role forming cluster S2D1. 

For documentation about AutomatedLab please refer to https://automatedlab.org/en/latest/

## Post Deployment Steps

Once the deployment is complete to access your Hyper-V Host, create an inbound security rule on your NAT Subnet NSG (or better, use just-in-time access or Bastion).

## Final Configuration

The environment in this guide has the below configurations. This section is intended to be used as a reference.

1. Azure Virtual Network Information.
    + VNet High Level Configuration.
        + Name: Nested-Fun
        + Address Space: 10.0.0.0/21
        + Note: This will be made up of four Subnets. Also, these ranges are not set in stone. Feel free to address your environment however you want.

    + First Subnet High Level Configuration.
        + Name: NAT
        + Address Space: 10.0.0.0/24
        + Note: This is where our Hyper-V hosts primary NIC resides. This will be used to handle outbound NAT for the nested VMs. It will be the gateway to the internet for your nested VMs.

    + Second Subnet High Level Configuration.
        + Name: Hyper-V-LAN
        + Address Space: 10.0.1.0/24
        + Note:  Our Hyper-V host will have a second NIC that will be used to handle the routing between the nested VMs and non-internet resources external to the Hyper-V host.

    + Third Subnet High Level Configuration.
        + Name: Ghosted
        + Address Space: 10.0.2.0/24
        + Note:  This will be a “floating” subnet. The address space will be consumed by our nested VMs and exists to handle route advertisements back to on-premises. No VMs will actually be deployed into this subnet.

    + Fourth Subnet High Level Configuration.
        + Name: Azure-VMs
        + Address Space: 10.0.3.0/24
        + Note: Subnet containing Azure VMs.

2. Our Hyper-V host has the below NIC configurations.
    + Primary NIC
        + IP Address: 10.0.0.4
        + Subnet Mask: 255.255.255.0
        + Default Gateway: 10.0.0.1
        + DNS: Configured for DHCP
        + IP Forwarding Enabled: No

    + Secondary NIC
        + IP Address: 10.0.1.4
        + Subnet Mask: 255.255.255.0
        + Default Gateway: Empty
        + DNS: Configured for DHCP
        + IP Forwarding Enabled: Yes

    + Hyper-V Created NIC for Internal Virtual Switch
        + IP Address: 10.0.2.1
        + Subnet Mask: 255.255.255.0
        + Default Gateway: Empty

3. Our Route Table will have a single rule.
    + Rule 1
        + Name: Nested-VMs
        + Destination: 10.0.2.0/24
        + Next Hop: Virtual Appliance - 10.0.1.4

Beyond this the solution does support network communication between on-premises resources and the nested virtual machines. To achieve this route tables will need to be created on the GatewaySubnet and additional routes created in RRAS on the Hyper-V Host
