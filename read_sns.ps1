# View SNS Incident Alert Messages from LocalStack
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
python (Join-Path $ScriptDir "read_sns.py")

