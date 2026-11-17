@echo off
set CONTAINER=localstack-ec2.i-cc08d7300dc4c19c8

echo Connecting to EC2 instance (Ubuntu 22.04)...
if "%~1"=="" (
    docker exec -it %CONTAINER% /bin/bash
) else (
    docker exec -i %CONTAINER% /bin/bash -c "%*"
)
