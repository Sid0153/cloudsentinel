"""The simulated AWS for CloudSentinel's sandbox mode: moto's server plus one addition.

moto answers S3 GetBucketPolicyStatus (GET /bucket?policyStatus) with an object listing, so
the scanner could never tell whether a bucket policy is public. This adds that operation
(see policy.py for how simplified it is) and otherwise runs moto unchanged.

Never expose this server to the internet: it accepts any credentials. In docker compose only
the backend can reach it.
"""

import os
from typing import Any

from moto.s3.responses import S3Response
from moto.server import main

from policy import policy_is_public, policy_status_xml

_original_bucket_get = S3Response._bucket_response_get


def _bucket_response_get(self: S3Response, bucket_name: str, querystring: dict[str, Any]) -> Any:
    if "policyStatus" not in querystring:
        return _original_bucket_get(self, bucket_name, querystring)
    bucket = self.backend.get_bucket(bucket_name)  # raises NoSuchBucket like AWS
    return 200, {}, policy_status_xml(policy_is_public(bucket.policy))


S3Response._bucket_response_get = _bucket_response_get  # type: ignore[method-assign]

if __name__ == "__main__":
    # 0.0.0.0 inside its own compose container (only the backend can reach it); 127.0.0.1 when
    # it shares the backend's container (deploy/Dockerfile).
    host = os.environ.get("SANDBOX_HOST", "0.0.0.0")  # noqa: S104
    main(["--host", host, "--port", os.environ.get("SANDBOX_PORT", "5000")])
