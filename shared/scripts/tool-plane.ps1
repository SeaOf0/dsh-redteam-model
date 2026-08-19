# tool-plane 探测合并（Windows/PowerShell）：一次跑完期望工具集的 Get-Command 探测，输出紧凑表
# 用法: .\tool-plane.ps1 -Tools tool1,tool2,...   （参数 = 本模式 playbook 附录 A/B 的期望工具清单）
# 可选: -Version 时附带版本首行探测（3 秒超时防交互卡死）
param(
	[Parameter(Mandatory = $true)][string[]]$Tools,
	[switch]$Version
)
foreach ($t in $Tools) {
	$c = Get-Command $t -ErrorAction SilentlyContinue
	if ($c) {
		$v = ""
		if ($Version) {
			try {
				$job = Start-Job -ScriptBlock { param($x) & $x --version 2>&1 | Select-Object -First 1 } -ArgumentList $t
				if (Wait-Job $job -Timeout 3) { $v = [string](Receive-Job $job | Select-Object -First 1); $v = $v.Substring(0, [Math]::Min(48, $v.Length)) }
				Remove-Job $job -Force -ErrorAction SilentlyContinue
			} catch { $v = "" }
		}
		if ($v) { Write-Output "tool-plane: $t ok | $v" } else { Write-Output "tool-plane: $t ok" }
	} else {
		Write-Output "tool-plane: $t missing"
	}
}
