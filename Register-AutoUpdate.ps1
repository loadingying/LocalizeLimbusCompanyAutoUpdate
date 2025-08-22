#Requires -Version 5.1
<#
  作用：以管理员身份运行 auto_update.exe --register
  说明：自动弹出 UAC 提权；工作目录设置为 exe 所在目录
#>

$ExePath = Join-Path $PSScriptRoot "auto_update.exe"
if (-not (Test-Path $ExePath)) {
  Write-Error "未找到 auto_update.exe：$ExePath"
  exit 1
}

# 以管理员身份运行，并等待完成
$psi = @{
  FilePath        = $ExePath
  ArgumentList    = @('--register')
  WorkingDirectory= $PSScriptRoot
  Verb            = 'RunAs'        # 申请管理员权限（弹 UAC）
  PassThru        = $true
  WindowStyle     = 'Hidden'
}
try {
  $p = Start-Process @psi
  $p.WaitForExit()
  if ($p.ExitCode -eq 0) {
    Write-Host "✅ 注册任务完成（exit code = 0）"
    exit 0
  } else {
    Write-Error "注册任务失败（exit code = $($p.ExitCode)）"
    exit $p.ExitCode
  }
}
catch {
  Write-Error "启动 auto_update.exe 失败：$($_.Exception.Message)"
  exit 1
}
