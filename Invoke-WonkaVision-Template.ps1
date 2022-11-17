function Invoke-WonkaVision {
    $EncodedCompressedFile = 'BINSTRING'
    $DeflatedStream = New-Object IO.Compression.GzipStream([IO.MemoryStream][Convert]::FromBase64String($EncodedCompressedFile),[IO.Compression.CompressionMode]::Decompress)
    $UncompressedFileBytes = New-Object Byte[](BINSIZE)
    $DeflatedStream.Read($UncompressedFileBytes, 0, BINSIZE) | Out-Null
    $Assembly = [Reflection.Assembly]::Load($UncompressedFileBytes)
    $BindingFlags = [Reflection.BindingFlags] "Public,Static"
    $a = @()
    $Assembly.GetType("WonkaVision.Program").GetMethod("Main").Invoke($Null, @(,[string[]]$args))
}
