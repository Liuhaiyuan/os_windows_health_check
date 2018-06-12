:: 提升powershell 执行权限
powershell -noprofile Set-ExecutionPolicy remotesigned -force
powershell -f ./Windows_Health_CheckV1.1.ps1