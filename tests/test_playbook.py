"""
Unit Tests for Multi-Service Incident Response Playbook and Verification Endpoints
"""

import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
import lambda_function
import mock_server


class TestIncidentResponsePlaybook(unittest.TestCase):

    @patch("lambda_function.get_boto_client")
    def test_successful_containment(self, mock_get_client):
        """Tests successful S3 lockdown, EC2 isolation, and SNS dispatch."""
        mock_s3 = MagicMock()
        mock_ec2 = MagicMock()
        mock_sns = MagicMock()

        def client_selector(service):
            if service == "s3":
                return mock_s3
            elif service == "ec2":
                return mock_ec2
            return mock_sns

        mock_get_client.side_effect = client_selector
        mock_sns.publish.return_value = {"MessageId": "msg-unit-test-123"}
        mock_ec2.describe_instances.return_value = {
            "Reservations": [
                {"Instances": [{"InstanceId": "i-test-123", "State": {"Name": "running"}}]}
            ]
        }
        mock_ec2.stop_instances.return_value = {
            "StoppingInstances": [{"InstanceId": "i-test-123"}]
        }

        event = {
            "body": json.dumps({
                "target_bucket": "production-data-vault",
                "operator": "lead-secops",
                "reason": "Accidental bucket policy exposure"
            })
        }

        response = lambda_function.lambda_handler(event, None)
        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(response["headers"]["Access-Control-Allow-Origin"], "*")

        payload = json.loads(response["body"])
        self.assertTrue(payload["success"])
        self.assertEqual(payload["status"], "CONTAINED_AND_LOCKED")
        self.assertEqual(payload["target_bucket"], "production-data-vault")
        self.assertIn("i-test-123", payload["stopped_ec2_instances"])

        # Verify S3 Public Access Block configuration
        mock_s3.put_public_access_block.assert_called_once_with(
            Bucket="production-data-vault",
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        )

        # Verify EC2 stop instances was called
        mock_ec2.stop_instances.assert_called_once_with(InstanceIds=["i-test-123"])

        # Verify SNS publish call
        mock_sns.publish.assert_called_once()
        publish_kwargs = mock_sns.publish.call_args[1]
        self.assertIn("CONTAINMENT", publish_kwargs["Subject"])

    @patch("lambda_function.get_boto_client")
    def test_default_fallback_values(self, mock_get_client):
        """Verifies handler gracefully falls back to default values when body is empty."""
        mock_s3 = MagicMock()
        mock_ec2 = MagicMock()
        mock_sns = MagicMock()
        mock_get_client.side_effect = lambda s: mock_s3 if s == "s3" else (mock_ec2 if s == "ec2" else mock_sns)
        mock_sns.publish.return_value = {"MessageId": "msg-unit-test-456"}
        mock_ec2.describe_instances.return_value = {"Reservations": []}

        response = lambda_function.lambda_handler({}, None)
        self.assertEqual(response["statusCode"], 200)

        payload = json.loads(response["body"])
        self.assertEqual(payload["target_bucket"], "confidential-company-data-2503a52928")
        self.assertTrue(payload["success"])

    @patch("lambda_function.get_boto_client")
    def test_s3_failure_handling(self, mock_get_client):
        """Verifies graceful handling and status reporting when S3 operation raises an exception."""
        mock_s3 = MagicMock()
        mock_s3.put_public_access_block.side_effect = Exception("NoSuchBucket")
        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {"Reservations": []}
        mock_sns = MagicMock()
        mock_get_client.side_effect = lambda s: mock_s3 if s == "s3" else (mock_ec2 if s == "ec2" else mock_sns)

        response = lambda_function.lambda_handler({"body": '{"target_bucket": "non-existent"}'}, None)
        self.assertEqual(response["statusCode"], 500)

        payload = json.loads(response["body"])
        self.assertFalse(payload["success"])
        self.assertEqual(payload["status"], "PARTIAL_FAILURE")
        self.assertIn("S3 lockdown failed", payload["errors"][0])

    def test_probe_public_access_transitions(self):
        """Tests that probe_public_s3 returns 403 when locked."""
        mock_server.MOCK_STATE["is_locked"] = True
        code, content, url = mock_server.probe_public_s3("confidential-company-data")
        self.assertEqual(code, 403)
        self.assertIn("AccessDenied", content)


if __name__ == "__main__":
    unittest.main()
