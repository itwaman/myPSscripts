while ($true) {
    Clear-Host;
    Get-DeliveryOptimizationStatus | Select-Object  PredefinedCallerApplication, 
            FileSize, 
            #TotalBytesDownloaded,
            @{Name='TotBytesDL';Expression={$_.TotalBytesDownloaded}},
            #DownloadMode,
            @{Name='DL-Mode';Expression={$_.DownloadMode}},
            Status,
            #BytesFromHTTP,
            @{Name='From-HTTP';Expression={$_.BytesFromHTTP}},
            @{Name='From-P2P';Expression={$_.BytesFromPeers}},
            #BytesFromPeers,
            #BytesFromCacheServer,
            @{Name='From-Cache';Expression={$_.BytesFromCacheServer}},
            #BytesToLanPeers,
            @{Name='To-P2P';Expression={$_.BytesToLanPeers}},
            NumPeers,
            #PercentPeerCaching,
            @{Name='%P2P-Caching';Expression={$_.PercentPeerCaching}},
            isPinned,
            ExpireOn,
            CacheHost,
            #FileId `
            @{Name='FileId';Expression={($_.FileId).replace('501FCB7D-A970-4E34-A753-4B48FE5D8BEF_dd525774-388a-4c66-a922-cb9335cab92e_','')}}`
            | Sort-Object PredefinedCallerApplication,FileSize |  Format-Table -Property * -AutoSize ;
    Start-Sleep -Seconds 2
}
