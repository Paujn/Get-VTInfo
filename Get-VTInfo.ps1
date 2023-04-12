<#PSScriptInfo
.VERSION 1.0
.GUID 2d1c927a-9029-4996-ab10-1202b7bb852f
.AUTHOR Sheyk
.COPYRIGHT 2023 Pau Juan Nieto
.TAGS Get VirusTotal Information
.LICENSEURI https://raw.githubusercontent.com/Paujn/Get-VTInfo/main/LICENSE
.EXTERNALMODULEDEPENDENCIES VirusTotalAnalyzer (https://github.com/EvotecIT/VirusTotalAnalyzer)
.RELEASENOTES Initial Release
#>

<# 
.SYNOPSIS
    Get VirusTotal Information.
.DESCRIPTION
    Get VirusTotal information about IP Addresses and domains via API from CSV sources.
.PARAMETER Path
    CSV source path.
.PARAMETER Column
    CSV Column Name.
.PARAMETER Type
    Type of request. (IP or Domain)
.PARAMETER API
    VirusTotal API Key.
.PARAMETER Export
    CSV export path.
.PARAMETER all
    Show results with zero positives.
.PARAMETER v
    Enable verbosity.
.EXAMPLE
    Get-VTInfo.ps1 -Source "C:\temp\ips.csv" -Column IPADDRESS -Type IP -API 693139e6d61c0b42806d5304f6382064964e64d433278b2d26e2834a72b014f9
.EXAMPLE
    Get-VTInfo.ps1 -Source "C:\temp\domains.csv" -Column DOMAINS -Type Domain -API 693139e6d61c0b42806d5304f6382064964e64d433278b2d26e2834a72b014f9 -all -Export C:\temp\result.csv
.LINK
    https://github.com/Paujn/Get-VTInfo
.NOTES
    Author: Pau Juan Nieto
#> 

Param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Path,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Column,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Type,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$API,
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$Export,
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [switch]$all,
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [switch]$v
)

# Load Modules

Import-Module VirusTotalAnalyzer -Force

# Table creation

$global:table = New-Object system.Data.DataTable 'DT'  
$newcol = New-Object system.Data.DataColumn IP,([string]); $global:table.columns.add($newcol)  
$newcol = New-Object system.Data.DataColumn Malicious,([int]); $global:table.columns.add($newcol)  
$newcol = New-Object system.Data.DataColumn Suspicious,([int]); $global:table.columns.add($newcol) 
$newcol = New-Object system.Data.DataColumn Country,([string]); $global:table.columns.add($newcol) 
$newcol = New-Object system.Data.DataColumn ASOwner,([string]); $global:table.columns.add($newcol)

# Delete duplicates and internal IP addresses

if($Type -like "IP"){
    if($v){Write-Host "Importing data..." -ForegroundColor Cyan}
    $IPS = Import-Csv -Path $Path | Select-Object -ExpandProperty $Column
    if($v){Write-Host "Purging duplicates..." -ForegroundColor Cyan}
    $IPS = $IPS | Select-Object -Unique
    if($v){Write-Host "Cleaning internal IPs..." -ForegroundColor Cyan}
    $global:IPS = $IPS | Where-Object { $_ -notmatch "^192\.168\." -and $_ -notmatch "^172\.(1[6-9]|2[0-9]|3[0-1])\." -and $_ -notmatch "^10\." }
}elseif($Type -like "Domain"){
    if($v){Write-Host "Importing data..." -ForegroundColor Cyan}
    $Domains = Import-Csv -Path $Path | Select-Object -ExpandProperty $Column
    if($v){Write-Host "Purging duplicates..." -ForegroundColor Cyan}
    $Domains = $Domains | Select-Object -Unique   
}else{
    Write-Host "Wrong -Type parameter, please use 'IP' or 'Domain' instead. Exiting the application..." -ForegroundColor Red
    Exit
}

# VT Requests via API
if($Type -like "IP"){
    foreach($IP in $global:IPS){

        if($v){Write-host "Requesting $IP via API" -ForegroundColor Yellow}

        $VTReport = Get-VirusReport -ApiKey $API -IPAddress $IP

        $row = $global:table.NewRow()  
        $row.IP= ($VTReport.data.id)  
        $row.Malicious= [int]($VTReport.data.attributes.last_analysis_stats.malicious)  
        $row.Suspicious= [int]($VTReport.data.attributes.last_analysis_stats.suspicious)  
        $row.Country= ($VTReport.data.attributes.country)
        $row.ASOwner= ($VTReport.data.attributes.as_owner)
        $global:table.Rows.Add($row)  

    }
}elseif($Type -like "Domain"){
    foreach($Domain in $Domains){

        if($v){Write-host "Requesting $Domain via API" -ForegroundColor Yellow}

        $VTReport = Get-VirusReport -ApiKey $API -DomainName $Domain

        $row = $global:table.NewRow()  
        $row.IP= ($VTReport.data.id)  
        $row.Malicious= [int]($VTReport.data.attributes.last_analysis_stats.malicious)  
        $row.Suspicious= [int]($VTReport.data.attributes.last_analysis_stats.suspicious)  
        $row.Country= ($VTReport.data.attributes.country)
        $row.ASOwner= ($VTReport.data.attributes.as_owner)
        $global:table.Rows.Add($row)  
        
    }
}

# Print results
if(!$all){
$Global:table | Sort-Object Malicious -Descending | Where-Object {$_.Malicious -ne 0 -or $_.Suspicious -ne 0} | FT
}else{
$Global:table | Sort-Object Malicious -Descending | FT
}

# Export
if($Export){$global:table | Export-CSV -Path $Export}

if($v){Write-Host "Results exported to $Export" -ForegroundColor Cyan}
