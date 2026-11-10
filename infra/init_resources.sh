#!/usr/bin/env bash
set -e

echo "============================================================"
echo "⚡ Initializing AWS Incident Response Panic Button Resources"
echo "============================================================"

AWS_REGION="us-east-1"
TARGET_BUCKET="confidential-company-data"
SNS_TOPIC_NAME="incident-response-panic-alerts"
LAMBDA_FUNCTION_NAME="IncidentResponsePanicHandler"
LAMBDA_ROLE_NAME="lambda-panic-execution-role"

# Detect whether running inside localstack container or on host with awslocal / aws
if command -v awslocal &> /dev/null; then
    AWS_CMD="awslocal"
elif command -v aws &> /dev/null; then
    AWS_CMD="aws --endpoint-url=http://localhost:4566 --region=${AWS_REGION}"
else
    AWS_CMD="aws --endpoint-url=http://localhost:4566 --region=${AWS_REGION}"
fi

echo "Using AWS CLI tool: ${AWS_CMD}"

# 1. Create S3 Bucket (Asset to be protected)
echo "📁 1. Creating target S3 Bucket: ${TARGET_BUCKET}..."
${AWS_CMD} s3 mb s3://${TARGET_BUCKET} 2>/dev/null || echo "Bucket already exists."

# Put sample confidential file
echo "id,customer_name,ssn,account_balance" > /tmp/customer_records.csv
echo "101,John Doe,XXX-XX-1234,\$54,200.00" >> /tmp/customer_records.csv
${AWS_CMD} s3 cp /tmp/customer_records.csv s3://${TARGET_BUCKET}/customer_records_2026.csv

# Intentionally leave or set public access enabled to simulate breach state
${AWS_CMD} s3api put-public-access-block \
    --bucket ${TARGET_BUCKET} \
    --public-access-block-configuration "BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false" \
    2>/dev/null || true
echo "✅ Target S3 Bucket initialized in VULNERABLE test state."

# 2. Create SNS Topic for Security Alerts
echo "📢 2. Creating Amazon SNS Topic: ${SNS_TOPIC_NAME}..."
TOPIC_ARN=$(${AWS_CMD} sns create-topic --name ${SNS_TOPIC_NAME} --query "TopicArn" --output text)
echo "✅ SNS Topic ARN: ${TOPIC_ARN}"

# Subscribe a default email
${AWS_CMD} sns subscribe \
    --topic-arn "${TOPIC_ARN}" \
    --protocol email \
    --notification-endpoint "secops-alert@company.internal" > /dev/null

# 3. Create IAM Execution Role for Lambda
echo "🛡️ 3. Creating IAM execution role..."
cat << 'EOF' > /tmp/trust-policy.json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Service": "lambda.amazonaws.com" },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

ROLE_ARN=$(${AWS_CMD} iam create-role \
    --role-name ${LAMBDA_ROLE_NAME} \
    --assume-role-policy-document file:///tmp/trust-policy.json \
    --query "Role.Arn" --output text 2>/dev/null || \
    ${AWS_CMD} iam get-role --role-name ${LAMBDA_ROLE_NAME} --query "Role.Arn" --output text)

# Attach administrator/power policy for LocalStack demo
${AWS_CMD} iam attach-role-policy \
    --role-name ${LAMBDA_ROLE_NAME} \
    --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess" 2>/dev/null || true

# 4. Package and Deploy Lambda Function
echo "📦 4. Packaging and Deploying Lambda Function: ${LAMBDA_FUNCTION_NAME}..."
if [ -f "/workspace/backend/lambda_function.py" ]; then
    PROJECT_DIR="/workspace"
    LAMBDA_CODE="/workspace/backend/lambda_function.py"
else
    SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
    PROJECT_DIR="${SCRIPT_DIR}/.."
    LAMBDA_CODE="${PROJECT_DIR}/backend/lambda_function.py"
fi

cd /tmp
rm -f lambda.zip
zip -j lambda.zip "${LAMBDA_CODE}" > /dev/null

${AWS_CMD} lambda delete-function --function-name ${LAMBDA_FUNCTION_NAME} 2>/dev/null || true

LAMBDA_ARN=$(${AWS_CMD} lambda create-function \
    --function-name ${LAMBDA_FUNCTION_NAME} \
    --runtime python3.9 \
    --timeout 15 \
    --role "${ROLE_ARN}" \
    --handler lambda_function.lambda_handler \
    --zip-file fileb:///tmp/lambda.zip \
    --environment "Variables={AWS_ENDPOINT_URL=http://${LOCALSTACK_HOSTNAME:-localhost}:4566,TARGET_BUCKET_NAME=${TARGET_BUCKET},SNS_TOPIC_ARN=${TOPIC_ARN}}" \
    --query "FunctionArn" --output text)
echo "✅ Lambda deployed: ${LAMBDA_ARN}"

# 5. Set up API Gateway REST API
echo "🌐 5. Configuring Amazon API Gateway..."
API_ID=$(${AWS_CMD} apigateway create-rest-api --name "IncidentPanicAPI" --query "id" --output text)
ROOT_ID=$(${AWS_CMD} apigateway get-resources --rest-api-id "${API_ID}" --query "items[?path=='/'].id" --output text)

RESOURCE_ID=$(${AWS_CMD} apigateway create-resource \
    --rest-api-id "${API_ID}" \
    --parent-id "${ROOT_ID}" \
    --path-part "panic" \
    --query "id" --output text)

# Add POST method with Lambda integration
${AWS_CMD} apigateway put-method \
    --rest-api-id "${API_ID}" \
    --resource-id "${RESOURCE_ID}" \
    --http-method POST \
    --authorization-type NONE > /dev/null

URI="arn:aws:apigateway:${AWS_REGION}:lambda:path/2015-03-31/functions/${LAMBDA_ARN}/invocations"

${AWS_CMD} apigateway put-integration \
    --rest-api-id "${API_ID}" \
    --resource-id "${RESOURCE_ID}" \
    --http-method POST \
    --type AWS_PROXY \
    --integration-http-method POST \
    --uri "${URI}" > /dev/null

# Add OPTIONS method for CORS
${AWS_CMD} apigateway put-method \
    --rest-api-id "${API_ID}" \
    --resource-id "${RESOURCE_ID}" \
    --http-method OPTIONS \
    --authorization-type NONE > /dev/null

${AWS_CMD} apigateway put-integration \
    --rest-api-id "${API_ID}" \
    --resource-id "${RESOURCE_ID}" \
    --http-method OPTIONS \
    --type MOCK > /dev/null

${AWS_CMD} apigateway put-method-response \
    --rest-api-id "${API_ID}" \
    --resource-id "${RESOURCE_ID}" \
    --http-method OPTIONS \
    --status-code 200 \
    --response-parameters "method.response.header.Access-Control-Allow-Headers=false,method.response.header.Access-Control-Allow-Methods=false,method.response.header.Access-Control-Allow-Origin=false" > /dev/null

${AWS_CMD} apigateway put-integration-response \
    --rest-api-id "${API_ID}" \
    --resource-id "${RESOURCE_ID}" \
    --http-method OPTIONS \
    --status-code 200 \
    --response-parameters "{\"method.response.header.Access-Control-Allow-Origin\":\"'*'\",\"method.response.header.Access-Control-Allow-Methods\":\"'POST,OPTIONS'\",\"method.response.header.Access-Control-Allow-Headers\":\"'Content-Type,X-Amz-Date,Authorization,X-Api-Key'\"}" > /dev/null

# Deploy stage 'prod'
${AWS_CMD} apigateway create-deployment --rest-api-id "${API_ID}" --stage-name prod > /dev/null

API_ENDPOINT="http://localhost:4566/restapis/${API_ID}/prod/_user_request_/panic"
echo ""
echo "============================================================"
echo "🎉 ALL AWS RESOURCES DEPLOYED TO LOCALSTACK!"
echo "API Endpoint: ${API_ENDPOINT}"
echo "S3 Bucket:    s3://${TARGET_BUCKET}"
echo "SNS Topic:    ${TOPIC_ARN}"
echo "Lambda:       ${LAMBDA_FUNCTION_NAME}"
echo "============================================================"

# Save config for frontend
cat << EOF > "${PROJECT_DIR}/frontend/config.js"
window.PANIC_CONFIG = {
    apiUrl: "${API_ENDPOINT}",
    targetBucket: "${TARGET_BUCKET}",
    snsTopicArn: "${TOPIC_ARN}",
    region: "${AWS_REGION}",
    mode: "localstack"
};
EOF
chmod +x "${PROJECT_DIR}/frontend/config.js" 2>/dev/null || true
echo "Config written to frontend/config.js"
