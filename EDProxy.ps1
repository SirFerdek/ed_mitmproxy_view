$lp = $(legendary.exe launch --dry-run 9c203b6ed35846e8a4a9ff1e314f6593 --override-exe MinEdLauncher.exe --skip-version-check 2>&1 | Out-String -Stream -Width 999999 | Select-String "Launch parameters:")
$slp = $lp.ToString().split(" ")
$executable = $slp[4].Trim("'")
$largs = $slp[5..$slp.Length]
Invoke-Command {
    $env:http_proxy = 'http://127.0.0.1:8080/'
    $env:https_proxy = $env:http_proxy
    & $executable $largs
    $env:http_proxy = ''
    $env:https_proxy = ''
}