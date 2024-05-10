$fileIds = Get-DeliveryOptimizationStatus | Select-Object FileId
foreach ($fileid in $fileids) {
    Set-DeliveryOptimizationStatus -Pin $true -FileId $fileid.fileid
}
