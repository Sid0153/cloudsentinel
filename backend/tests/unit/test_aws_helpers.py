from botocore.exceptions import ClientError, NoCredentialsError

from app.aws.collectors.s3 import bucket_region
from app.aws.common import Collected, error_code, error_label
from app.scans.discovery import MAX_ERRORS_PER_SERVICE, coverage_entry


def _client_error(code: str, message: str = "") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": message}}, "SomeOperation")


def test_bucket_region_handles_aws_quirks() -> None:
    assert bucket_region(None) == "us-east-1"
    assert bucket_region("") == "us-east-1"
    assert bucket_region("EU") == "eu-west-1"
    assert bucket_region("ap-south-1") == "ap-south-1"


def test_error_label_keeps_code_and_drops_aws_message() -> None:
    exc = _client_error("AccessDenied", "arn:aws:iam::123456789012:user/secret-name is not allowed")
    assert error_code(exc) == "AccessDenied"
    assert error_label("ListBuckets", exc) == "AccessDenied (ListBuckets)"
    assert "secret-name" not in error_label("ListBuckets", exc)
    assert error_label("Connect", NoCredentialsError()) == "NoCredentialsError (Connect)"


def test_coverage_status_succeeded_partial_failed() -> None:
    assert coverage_entry(Collected(raw=None, items=3))["status"] == "SUCCEEDED"
    assert coverage_entry(Collected(raw=None, errors=["x"], items=3))["status"] == "PARTIAL"
    assert coverage_entry(Collected(raw=None, errors=["x"], items=0))["status"] == "FAILED"


def test_coverage_error_list_is_capped_but_counted() -> None:
    errors = [f"bucket-{i}: AccessDenied (GetBucketAcl)" for i in range(50)]
    entry = coverage_entry(Collected(raw=None, errors=errors, items=50))
    assert entry["error_count"] == 50
    assert len(entry["errors"]) == MAX_ERRORS_PER_SERVICE
