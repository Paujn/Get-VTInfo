# Get-VTInfo
Get VirusTotal information about IP Addresses and domains via API from CSV sources.

Requires VirusTotalAnalyzer (https://github.com/EvotecIT/VirusTotalAnalyzer) to be installed for it to work.

-SYNOPSIS
Get VirusTotal Information.

-DESCRIPTION
Get VirusTotal information about IP Addresses and domains via API from CSV sources.

-PARAMETER Path
CSV source path.

-PARAMETER Column
CSV Column Name.

-PARAMETER Type
Type of request. (IP or Domain)

-PARAMETER API
VirusTotal API Key.

-PARAMETER Export
CSV export path.

-PARAMETER all
Show results with zero positives.

-PARAMETER v
Enable verbosity.

-EXAMPLE
Get-VTInfo.ps1 -Source "C:\temp\ips.csv" -Column IPADDRESS -Type IP -API 693139e6d61c0b42806d5304f6382064964e64d433278b2d26e2834a72b014f9

-EXAMPLE
Get-VTInfo.ps1 -Source "C:\temp\domains.csv" -Column DOMAINS -Type Domain -API 693139e6d61c0b42806d5304f6382064964e64d433278b2d26e2834a72b014f9 -all -Export C:\temp\result.csv

-LINK
https://github.com/Paujn/Get-VTInfo

-NOTES
Author: Pau Juan Nieto
