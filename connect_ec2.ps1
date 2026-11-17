# Connects directly to the EC2 container (Ubuntu 22.04)
$containerName = "localstack-ec2.i-cc08d7300dc4c19c8"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$KeyPath = Join-Path $ScriptDir "infra\ec2\key.pem"

Write-Host "Connecting to EC2 instance (Ubuntu 22.04)..." -ForegroundColor Cyan

if ($args.Count -eq 0) {
    # Open interactive bash session inside the EC2 container
    docker exec -it $containerName /bin/bash
} else {
    # Run command inside container
    docker exec -i $containerName /bin/bash -c "$args"
}
