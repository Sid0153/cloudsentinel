from app.findings.fingerprint import fingerprint

KEY = ("us-east-1", "AWS::EC2::SecurityGroup", "sg-1")


def test_fingerprint_is_stable_and_sha256_hex() -> None:
    value = fingerprint("123456789012", "CS-SG-001", KEY)
    assert value == fingerprint("123456789012", "CS-SG-001", KEY)
    assert len(value) == 64 and int(value, 16) >= 0


def test_each_part_of_the_identity_changes_the_fingerprint() -> None:
    base = fingerprint("123456789012", "CS-SG-001", KEY)
    variants = {
        fingerprint("111122223333", "CS-SG-001", KEY),
        fingerprint("123456789012", "CS-SG-003", KEY),
        fingerprint("123456789012", "CS-SG-001", ("eu-west-1", KEY[1], KEY[2])),
        fingerprint("123456789012", "CS-SG-001", (KEY[0], KEY[1], "sg-2")),
    }
    assert base not in variants and len(variants) == 4
