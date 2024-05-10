while ($true) {
    Clear-Host;
    Get-DeliveryOptimizationStatus | Select-Object  PredefinedCallerApplication, 
            FileSize, 
            TotalBytesDownloaded,
            DownloadMode,
            Status,
            BytesFromHTTP,
            BytesFromPeers,
            BytesToLanPeers,
            NumPeers,
            PercentPeerCaching,
            isPinned,
            ExpireOn,
            FileId | Sort-Object PredefinedCallerApplication,FileSize |  Format-Table -Property * -AutoSize ;
    Start-Sleep -Seconds 2
}
