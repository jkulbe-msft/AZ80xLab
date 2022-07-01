$GPOFolders = Get-ChildItem -Directory -Path $PSScriptRoot
foreach ($GPOFolder in $GPOFolders)
{
    $GPOBackups = Get-ChildItem -Directory -Path $GPOFolder.FullName
    foreach ($GPO in $GPOBackups)
    {
        [xml]$manifest = Get-Content $(Join-Path -Path $GPO.FullName -ChildPath bkupinfo.xml)
        Write-Output "Processing $($manifest.backupinst.gpodisplayname.'#cdata-section')"
        Import-GPO -Path $GPOFolder.FullName -BackupGPOName $manifest.backupinst.gpodisplayname.'#cdata-section' -TargetName $manifest.backupinst.gpodisplayname.'#cdata-section' -CreateIfNeeded
    }
}