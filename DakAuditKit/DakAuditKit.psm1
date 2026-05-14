$ErrorActionPreference = "Stop"

$privateDir = Join-Path $PSScriptRoot "private"
$publicDir  = Join-Path $PSScriptRoot "public"

foreach ($file in [System.IO.Directory]::GetFiles($privateDir, "*.ps1", [System.IO.SearchOption]::AllDirectories)) {
    try   { . $file }
    catch { Write-Error "Failed to import $file`: $_" }
}

$publicFunctions = @()
foreach ($file in [System.IO.Directory]::GetFiles($publicDir, "*.ps1", [System.IO.SearchOption]::AllDirectories)) {
    try {
        . $file
        $publicFunctions += [System.IO.Path]::GetFileNameWithoutExtension($file)
    } catch {
        Write-Error "Failed to import $file`: $_"
    }
}

Export-ModuleMember -Function $publicFunctions
