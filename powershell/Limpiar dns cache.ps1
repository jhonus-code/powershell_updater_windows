Write-Host "Buscando cache... " -ForegroundColor Magenta
Get-DNSClientCache
Clear-DnsClientCache
Write-Host "Cache Limpiada" -ForegroundColor Green
Get-DNSClientCache
Read-Host -Indicador «Presione Enter para salir»