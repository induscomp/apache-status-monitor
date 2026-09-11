import pyotp
import pytest

from app import cli
from app.config import get_settings


@pytest.mark.parametrize("valid_code", [True, False])
def test_qr_enrollment_requires_code_from_encoded_account(monkeypatch, capsys, valid_code):
    encoded = []
    make_qr = cli.segno.make_qr

    def capture_qr(uri):
        encoded.append(pyotp.parse_uri(uri))
        return make_qr(uri)

    monkeypatch.setattr(cli.segno, "make_qr", capture_qr)
    monkeypatch.setattr(
        cli.getpass,
        "getpass",
        lambda prompt: encoded[0].now() if valid_code else "invalid",
    )
    if valid_code:
        encrypted, recovery = cli.enrol_totp("admin@example.test")
        assert get_settings().cipher().decrypt(encrypted.encode()).decode() == encoded[0].secret
        assert len(set(recovery)) == 8
    else:
        with pytest.raises(SystemExit, match="No se ha guardado ningún cambio"):
            cli.enrol_totp("admin@example.test")

    assert encoded[0].name == "admin@example.test"
    assert encoded[0].issuer == "Apache Status Monitor"
    assert encoded[0].digits == 6
    assert encoded[0].interval == 30
    # The real terminal renderer ran, including explicit colors for either terminal theme.
    assert "\x1b[" in capsys.readouterr().out
