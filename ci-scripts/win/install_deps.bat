:: install choco
@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))" && SET "PATH=%PATH%;%ALLUSERSPROFILE%\chocolatey\bin"
:: install msys2
C:\ProgramData\chocolatey\bin\choco.exe install msys2 --yes
:: update msys2
C:\tools\msys64\usr\bin\pacman.exe --noconfirm --ask 20 --sync --refresh --refresh --sysupgrade --sysupgrade