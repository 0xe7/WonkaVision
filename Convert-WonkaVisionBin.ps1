function Convert-WonkaVision {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)]
        [string] $BinFile = $(Throw("-BinFile is required")),

        [Parameter(Mandatory)]
        [string] $TemplateFile = $(Throw("-TemplateFile is required"))
    )
    Process {
        try {
            $byteArray = [System.IO.File]::ReadAllBytes($BinFile)
        } catch {
            Write-Error "Unable to read file $(BinFile), make sure the path is correct and try using the full path."
            return
        }
        Write-Output "Size: $($byteArray.Length)"
        Write-Output "Compressing $($BinFile)"
       	[System.IO.MemoryStream] $output = New-Object System.IO.MemoryStream
        $gzipStream = New-Object System.IO.Compression.GzipStream $output, ([IO.Compression.CompressionMode]::Compress)
      	$gzipStream.Write( $byteArray, 0, $byteArray.Length )
        $gzipStream.Close()
        $output.Close()
        Write-Output "Base64 Encoding"
        $tmp = [Convert]::ToBase64String($output.ToArray())
        Write-Output "Writing output to .\Invoke-WonkaVision.ps1"
        (Get-Content $TemplateFile).Replace("BINSIZE", $byteArray.Length).Replace("BINSTRING", $tmp) | Set-Content -Path "Invoke-WonkaVision.ps1"
    }
}
