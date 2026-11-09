import pytest

from app.mac import MacError, format_mac, normalize_mac, try_mac


@pytest.mark.parametrize("value", ["b4:96:91:22:67:d1", "B4-96-91-22-67-D1", "b496.9122.67d1", "B496912267D1",
                                   "b496912267d1", "  b4:96:91:22:67:d1 "])
def test_every_common_notation_normalises(value):
    assert normalize_mac(value) == "B496912267D1"


@pytest.mark.parametrize("value", ["", "b4:96:91:22:67", "b4:96:91:22:67:d1:00", "b4-96:91-22:67-d1", "g4:96:91:22:67:d1",
                                   "b4969.12267d1", "b4 96 91 22 67 d1", "00:00:00:00:00:00", "01:00:5e:00:00:01",
                                   "ff:ff:ff:ff:ff:ff", "33:33:00:00:00:01"])
def test_rejects_malformed_group_and_zero(value):
    with pytest.raises(MacError):
        normalize_mac(value)


def test_try_and_format():
    assert try_mac("B4-96-91-22-67-D1") == "B496912267D1"
    assert try_mac("00-00-00-00-00-00") is None
    assert try_mac(None) is None
    assert format_mac("B496912267D1") == "B4:96:91:22:67:D1"
