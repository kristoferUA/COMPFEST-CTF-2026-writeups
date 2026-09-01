import hashlib


def test_flag_suffix():
    secret = "5e9e8bf77207eca9c6906e80a57aa0e426f18ab8825a7b0f656cfa5d888a81c9"
    assert hashlib.sha256(secret.encode()).hexdigest()[:16] == "aefbd0dc566889bb"
