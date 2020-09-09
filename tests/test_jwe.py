import json

import pytest
import six

import jose.backends
from jose import jwe
from jose.constants import ALGORITHMS, ZIPS
from jose.exceptions import JWEParseError
from jose.jwk import AESKey
from jose.jwk import RSAKey
from jose.utils import base64url_decode

backends = []
try:
    import jose.backends.cryptography_backend  # noqa E402
    backends.append(jose.backends.cryptography_backend)
except ImportError:
    pass
try:
    import jose.backends.pycrypto_backend  # noqa E402
    backends.append(jose.backends.pycrypto_backend)
except ImportError:
    pass
import jose.backends.native  # noqa E402

try:
    from jose.backends.rsa_backend import RSAKey as RSABackendRSAKey
except ImportError:
    RSABackendRSAKey = None

backends.append(jose.backends.native)

PRIVATE_KEY_PEM = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA3AyQGW/Q8AKJH2Mfjv1c67iYcwIn+Z2tpqHDQQV9CfSx9CMs
+Zg2buopXJ7AWd03ZR08g9O2bmlJPIQV1He3vfzZH9+6aJAQLJ+VzpME2sXl5Boa
yla1JjyoH7ix/i02QHDTVClDMb6dy0rMVpc7cBxwgX54fcR5x3AMscYCTQrhQc7q
YRzoLTfP9lGJT1DgyGcOt4paa77z4uqqaQxQ4QqxM9in3DU0mzVxXigHVakjiS6v
kSNEhSl+VLIp1sHiOhOSpcxWkhTikjm+XpwE5H0L9I1mQ2e2nTvX7uADg/pgFMy0
uP833rQzTxNqTTPJZFLtLkTyq1Hr2MUeQ3dRNQIDAQABAoIBAFK9+pVGAVeubGc7
+4rl5EHSqKheQC/RRZGps+TILotG0n9NlsTHong0XpcwLn3b+89unemn+yorNtml
hRveZF3xLKealdppiVtuKoOBrsqgrWAHHNnGntkg58r9xRghYgv7IMu9tEGJPoZJ
uuo4daYjW36l0qLf9Ta0AGH8ZbMX2LnNO+r4EQmZ1YJShEYOS94WJnFB7XuZ/bQH
AI3IRPkQvXQNq1nnMxhAj91hOhJvTVCS04yVVzMkntcpeNP7pc7ARtSA5IepJvdK
HbcoSQ1aIK/NPkhiDs/KOoWdnB8Mqr3fXFTVJ3/YTJKwODugJ5QCbSyIC8JewgIn
d6mA6iECgYEA7028RNk65c5NRkv6rkveTT1ybrvYUUO/pbAlS4MqZmtx69n4LFrW
qicXw7sJd+O8emyvF3xHPAfVviJKg6yudtI0nM9WUuOgKr+qoKRWJMpspXdpjTXs
AQXrFAJjrDIFujsbnRmT2nbRX8nSBWvI5oSG4JqILWYs0OdchIkPo0kCgYEA62bq
mjnlz7Mqvznf8b9jOSEJKub81aUz/fK62gXcEdvffUdlDecAzotjryI678TvEBpI
w1rmHLND60o+Lczd3quyEPQfYrf8P4/6sqGfE/QtB7zKR1bXmkV0dNlr9h6zpm/Y
BpLNiqr3Ntf4OCkKiD6ch+sZ4NjKBCwzodolUo0CgYEAk/PEzfBcqM5nGmpJX8/K
bojqIiqDcKLpb4A7XreG1HHjqkVGWe4DwImQ+NO/497qnepqSqPsyuGxNe+vkD+I
UjBelQDfxzmywhtkXBOeqvp4N8lfeg33jx5gnCtqAoGe5ug6h2PT9QL3Kjj2X6Gn
QVZ4qY8BWMhONw6ENfEjuPkCgYBP0ps05vMdpgSVyXs9z4dG5QPlz2Pm0lk6AKgJ
rDj+uU8kfSQwPafRYgTQa0wO5/mkvTT1QYqMKuGaFJfXEgQeMJx2EUHfSMI5j4oU
LqfxrTfjysnQvQrpHioqQVvRnoGOq5hWSkt2fRjNORjLemc+4fRURo2E6B5Aofh0
JrPHNQKBgBGYzDGJyFnu7GYTby18aPNkQYweNDM6aZ/tUN8yZ4ryq7QnodiKLe2b
VxSr8Y+1w4xRjN67PGrS3IpQX9CAoTqyBN7VLhuq/mixOPccmo/5ui3fig/WEYwK
+ox4tfIuhfmskPNS235vLwbNIBkzP3PWVM5Chq1pEnHQUeiZq3U+
-----END RSA PRIVATE KEY-----
"""

PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3AyQGW/Q8AKJH2Mfjv1c
67iYcwIn+Z2tpqHDQQV9CfSx9CMs+Zg2buopXJ7AWd03ZR08g9O2bmlJPIQV1He3
vfzZH9+6aJAQLJ+VzpME2sXl5Boayla1JjyoH7ix/i02QHDTVClDMb6dy0rMVpc7
cBxwgX54fcR5x3AMscYCTQrhQc7qYRzoLTfP9lGJT1DgyGcOt4paa77z4uqqaQxQ
4QqxM9in3DU0mzVxXigHVakjiS6vkSNEhSl+VLIp1sHiOhOSpcxWkhTikjm+XpwE
5H0L9I1mQ2e2nTvX7uADg/pgFMy0uP833rQzTxNqTTPJZFLtLkTyq1Hr2MUeQ3dR
NQIDAQAB
-----END PUBLIC KEY-----
"""

OCT_128_BIT_KEY = b"\x04\xd3\x1f\xc5T\x9d\xfc\xfe\x0bd\x9d\xfa?\xaaj\xce"
OCT_192_BIT_KEY = b"\x04\xd3\x1f\xc5T\x9d\xfc\xfe\x0bd\x9d\xfa?\xaaj\xcek|\xd4-ok\t\xdb"
OCT_256_BIT_KEY = b"\x04\xd3\x1f\xc5T\x9d\xfc\xfe\x0bd\x9d\xfa?\xaaj\xcek|\xd4-ok\t\xdb\xc8\xb1\x00\xf0\x8f\x9c,\xcf"
OCT_384_BIT_KEY = b"\x04\xd3\x1f\xc5T\x9d\xfc\xfe\x0bd\x9d\xfa?\xaaj\xcek|\xd4-ok\t\xdb\xc8\xb1\x00\xf0\x8f\x9c,\xcf\x04\xd3\x1f\xc5T\x9d\xfc\xfe\x0bd\x9d\xfa?\xaaj\xce"
OCT_512_BIT_KEY = b"\x04\xd3\x1f\xc5T\x9d\xfc\xfe\x0bd\x9d\xfa?\xaaj\xcek|\xd4-ok\t\xdb\xc8\xb1\x00\xf0\x8f\x9c,\xcf\x04\xd3\x1f\xc5T\x9d\xfc\xfe\x0bd\x9d\xfa?\xaaj\xcek|\xd4-ok\t\xdb\xc8\xb1\x00\xf0\x8f\x9c,\xcf"


class TestGetUnverifiedHeader(object):

    def test_valid_header_and_auth_tag(self):
        expected_header = {u"alg": u"RSA1_5", u"enc": u"A128CBC-HS256"}
        jwe_str = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." \
                  "UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7" \
                  "Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgN" \
                  "Z__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRir" \
                  "b6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8" \
                  "OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0m" \
                  "cKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A" \
                  "." \
                  "AxY8DCtDaGlsbGljb3RoZQ." \
                  "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY." \
                  "9hH0vgRfYgPnAHOd8stkvw"
        actual_header = jwe.get_unverified_header(jwe_str)
        assert expected_header == actual_header

    def test_invalid_jwe_string_raises_jwe_parse_error(self):
        with pytest.raises(JWEParseError):
            jwe.get_unverified_header("invalid jwe string")

    def test_non_json_header_section_raises_jwe_parse_error(self):
        jwe_str = "not json." \
                  "UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7" \
                  "Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgN" \
                  "Z__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRir" \
                  "b6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8" \
                  "OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0m" \
                  "cKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A" \
                  "." \
                  "AxY8DCtDaGlsbGljb3RoZQ." \
                  "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY." \
                  "9hH0vgRfYgPnAHOd8stkvw"

        with pytest.raises(JWEParseError):
            jwe.get_unverified_header(jwe_str)

    def test_wrong_auth_tag_is_ignored(self):
        expected_header = {u"alg": u"RSA1_5", u"enc": u"A128CBC-HS256"}
        jwe_str = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." \
                  "UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7" \
                  "Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgN" \
                  "Z__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRir" \
                  "b6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8" \
                  "OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0m" \
                  "cKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A" \
                  "." \
                  "AxY8DCtDaGlsbGljb3RoZQ." \
                  "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY." \
                  "invalid"
        actual_header = jwe.get_unverified_header(jwe_str)
        assert expected_header == actual_header


@pytest.mark.skipif(AESKey is None, reason="Test requires AES Backend")
@pytest.mark.skipif(RSAKey is RSABackendRSAKey, reason="RSA Backend does not support all modes")
class TestDecrypt(object):

    JWE_RSA_PACKAGES = (
        pytest.param(
            b"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.qHxZy-MfqRjCDAieY5AoU75XRGS7S-Xx4NytHgNa5dmGh9R8q1riHyPw5Hec_D395fKqV75u1hKke5r-jgiDTaCicQjOuxM2cSaiFlUid7dk5zIucaKH84N8jMzq3PwBePmGftePM2NMCzs6RvWBFP5SnDHh95NU2Xd-rIUICA7zIBXTwNRsB2LM9c_TZv1qh59DYoiSHWy94WXJBNFqViuVLmjVz5250J6Q4uRiYKGJKEGkfLDUp18N97aw5RQ35jJF6QyO5JkeLFTA0L10QAEtM8RjBRrKYgJ6fJLCVbHHTf7EKdn6Z-4cIZKtYe2d7PPKa0ZWZvtYTuU1S6DgmA.gdSr6lSIci4GjzMsdLaK6g.4ynh6gGG4dzxpmNfZHo6o8Eqp1eXRhKzI2Tmde-IulU.cFUhLtodRUqZ1GfSO6e3pw",
            id="alg: RSA1_5, enc: A128CBC-HS256"
        ),
        pytest.param(
            b"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0.Ju8YCub_jjFt4WR_pOIyeiXLtfwhUl-FMNETu3PMRVV8v6pD2-X4AFNWeA2pAX1_DkUIJEP8J3mjFdZB_ah6wb1ab0je-aSk3d8di8ES93gv_DkwWHkz_cjbm2At3JEh2gO252O3Ychjn8C0gMnLiXJN9Qmg_nF1drpvSdhgFz0FEI-2NlhD-0d8yy0ROMaMEby7aX7ouXP6QI3PKiwFYgPB-dtMzvF2cmZl_g3sLde9l1-U2e8JIpAW8vqQCO8Jswr0B6nH_LjUIBUEWS5vipqTa_v9siaAgLI46T5kEMJhnRVjJHvIkfnFABn5fCCVtgx2VpVrNkcejqvfLjIyNg.qyfq0GH9NgQOjuyEIKRQdA.FUb4QogxGaOslBqaTlcYqGGmhMXS8uTXNY0mpV7VPkQ.gi1jZcKEJoBey_5YBxSFVDnZulAlRPkq",
            id="alg: RSA1_5, enc: A192CBC-HS384"
        ),
        pytest.param(
            b"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0.2r5K6UQ4a8PDar1lpsLBNnMSwPuffn3vVnI-fbFCBKTzRUSgzWiMYKd9PCBFQIA5D3E8bwQiMY0tgiHNuCZF4PaLJp99SVKkbwp0H5681mFgpQ5c-QtPHMa5fA7_zOt1DRN67XddKTSKLm7_3RQ2twU4rg3DVS-aElZZSV74Rip_KKeoDvaoJBfPY4HPFqiR96dHLdLCoSzks1XzmRxo36cY2wb-4ztWUd2J5-_7ps1khUvffOMFJuox2zk9FYIqHXZQr9eL3n4cdF-M-tFvfjBenUThW97byckr1gyWzHCUOcaVHAP3jp1xubPahtkCpsOGAvqwiO9ahRtY0afhyw.xTKBz19OoA1Av0OfNVPgOg.FCNLcCHaOGBjQSLw8vJ_2K5ROdsm0m8YkKdkSGGzX98.M5fPe-ZDlF9xjS6YELgFS30sllUK_5FZ0vBqmmKCWpY",
            id="alg: RSA1_5, enc: A256CBC-HS512"
        ),
        pytest.param(
            b"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4R0NNIn0.QYbUBjDR7tf1NsbLOsVg3oub--eOgcm-a9BWJ3VIlwUWlE6ybdNFY-tgib69bFeDVJUgFipGbjpx99xbsn12F4dIZvDy0S9XWqKZ4GHXCtcButxyxyusQl-Qw0Myfd9OFEDmCnjCcU_Z2UamlsSK5c9OQa9F832bwlsOvufvexAUIoqNI94J6MCzWYn03zNcuKXd2EzbTXWRcxUL5RMQ_fFJb5mVEoRArw5H0Q9vCsjUkBGfvrLNr810yZrOIZLKrUW5Gq7vK2RR8GrPX1R1NIIrWe7FJgp1qr18-74q2vkNA8oGQitH1s0UJXXYObrJYZUZMGDh5NkGHyct1MwAqg.6GmP0pU4BfLq9vft.Lr_B5NID1Jsz1E-N9Hxz4PM7XV99sg.vNGa4jT1-N3eb7MZoj7REA",
            id="alg: RSA1_5, enc: A128GCM"
        ),
        pytest.param(
            b"eyJlbmMiOiJBMTkyR0NNIiwiYWxnIjoiUlNBMV81In0.pGI9inTliv1C52i9XOAVEXTcNR_KpOrK-flxdabnRFCCqVJDmvpoE1dO84FBTC0e0lSkfuGOdXOqOhgNho-rwtpKGeuAkk1X8NPmi-Cre6_hyZRcn-0M7tn4oqN-4JIh4FXSiMEJQfu2w7wTtZLX7FQvNRWYwl0klx_VB29rCEECTxvBDORmgT5N8WaEvqHb75X1SmO-t3JAlej2lJGKlrgThH7c5SUx0g702ccaMqORJ46JXKGGABqAUSwWpXozj5MimKg1UgVT6pXdj7MQtcMv_mhL7HIbUUZdTjbnkKmU-AH8rwJdIXsR5vosnzv_xOxf4BSOutkjqCBD7-psFw.AMBAA8ZpTm0c96TS.ehGiMXxn8bcH0yPmi9_d47UKc1C9hA.FyF6Wl57itn_W5hphdkXDA",
            id="alg: RSA1_5, enc: A192GCM"
        ),
        pytest.param(
            b"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2R0NNIn0.FmKpIISKPpeA45DVJFzuHuZzuDBc9OblwI1pa80rwlKVB7GhhTpd4aXYWRLU4qMNUfGj_Imlxc0rYdOfPa1IvCrrED9KjR5H604ruZgJZigoYCkS3WnAUnMCIOaDSP_Ye2UC4OTwnDSXRIdgnoyM-g9l3fOjgSeoc2aCSRE5DGHrgEpvzaFWDl4YDD_im7IsFEM8H7H2TAlN7ftkbKN6jd9MMRDXd6y7HYvNm4Hi_gPDM70TWhj-LIb6NmJE19EAboy8Ul8HAFdaCAFxwlLa6tFQyOuw-PLnZQ_soLGZXUeFNuYOafIjmPL2tgJiHfj1K_IPZwmWZS2d4I45He3CRA.xAUHSwvfz51m45eo.XeSm9hkA2mUNPk9eiaZx-I7mY4ZJqg.T0S3B4H4KusBzyZos81EIQ",
            id="alg: RSA1_5, enc: A256GCM"
        ),
        pytest.param(
            b"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhDQkMtSFMyNTYifQ.wQh8pyyAMCQRMAeMMIXStaoBCytZ4Upd7hFqpGxkoHq6aCDjjXywERJqgx68co_vz29JkTlK0Z2UsUOLjM4M6TeEiKgw0zT7ENXehP6VeE0bo2_cCx0k8A_af2eJXpsaqIvRsdkqYCsSW96H_eq3PoqOx96DNWTHxY5OTDjthr8B5WCYx3qA1oepT1HXSfCDB_01Qg-OREMu6l4Qc3i-ci6kQfhoAHb-sowpM8tUPvOx28z9-3a5_HxWMh0jFez86d9RHCecJx1UxHMJ6GSCzd2ra2xKi1gqaiC8MZupjvVJeGEpb4uriFmw5zJ9YGnefLj9NPMvj79XTrjD4AalaA.o9RgfKTIB5wbkrRr-wkO0Q.7ejS9gM307dU3to_V3AtqukA14IhuFyLrRG9RmRH2cw.hXUMRYby8afLVMI3H-WHYw",
            id="alg: RSA-OAEP, enc: A128CBC-HS256"
        ),
        pytest.param(
            b"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExOTJDQkMtSFMzODQifQ.u3QeBm1xbLlQSoDZJ5QFLT5KnTBvxHuh5WCb4Yt-jRVipJ_7DWBORoAsFXV-SB3oIeRlchcPX0QK2bz_uxFxNZGF9aLgROZXmyFGUs-S_6mewqnxiCgWcgM1fOvast6d65_Zrp8kgz8oev4EiuXwb2X1OO31BEOn3aZR7QGdD6O59q6pF79OU328hpKatqBjW4IdIgg68rtA2-87Xj9VqpqUBkgzJCf-z038yQR41GNVTRzMk6N2M3MgRYUFkqUHy59TRwplWQuRZ9vmkdotRGYI0ZQ7V5PzXhqYSJnx5Y9jYlIqv7sdz_b6lyqxkrtJGBRNfAFiil4HABIobx5YDw.2oKvl74hWoa3zpABph4L9Q.04KyNsCkVQAX-s547eYJOfj6SBR3cZypu2qy7ua4DUg.AKJwqOIH7wK3_7n_DmvZ96yq1vm3d6Mh",
            id="alg: RSA-OAEP, enc: A192CBC-HS384"
        ),
        pytest.param(
            b"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZDQkMtSFM1MTIifQ.Kbd5rSN1afyre2DbkXOmGKkCNZ09TfAwNpDn1Ic7_HJNS42VDx584ReiEzpyIoWek8l87h1oZL0OC0f1ceEuuTR-_rZzKNqq6t44EvXvRusSHg_mTm8qYwyJIkJsD_Zgh0HUza20X6Ypu4ZheTzw70krFYhFnBKNXzhdrf4Bbz8e7IEeR7Po2VqOzx6JPNFsJ1tRSb9r4w60-1qq0MSdl2VItvHVY4fg-bts2k2sJ_Ub8VtRLY1MzPc1rFcI10x_AD52ntW-8T_BvY8R7Ci0cLfEycGlOM-pJOtJVY4bQisx-PvLgPoKlfTMX251m_np9ImSov9edy57-jy427l28g.w5rYu_XKzUCwTScFQ3fGOA.6zntLreCPN2Eo6aLmuqYrkyF2hOBXzNlArOOJ0iZ9TA.xiF5HLIBmIE8FCog-CZwXpIUjP6XgpncwXjw--dM57I",
            id="alg: RSA-OAEP, enc: A256CBC-HS512"
        ),
        pytest.param(
            b"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhHQ00ifQ.SUDoqix7_PhGaNeCxYEgmvZt-Bhj-EoPfnTbJpxgvdUSVk6cn2XjAJxiVHTaeM8_DPmxxeKqt-JEVljc7lUmHQpAW1Cule7ySw498OgG6q4ddpBZEPXqAHpqlfATrhGpEq0WPRZJwvbyKUd08rND1r4SePZg8sag6cvbiPbMHIzQSjGPkDwWt1P5ue7n1ySmxqGenjPlzl4g_n5wwPGG5e3RGmoiVQh2Stybp9j2fiLNzHKcO5_9BJxMR4DEB0DE3NGhszXFQneP009j4wxm5kKzuja0ks9tEdNAJ3NLWnQhU-w0_xeePj8SGxJXuGIQT0ox9yQlD-HnmlEqMWYplg.5XuF3e3g7ck1RRy8.VSph3xlmrPI3z6jcLdh862GaDq6_-g.3WcUUUcy1NZ-aFYU8u9KHA",
            id="alg: RSA-OAEP, enc: A128GCM"
        ),
        pytest.param(
            b"eyJlbmMiOiJBMTkyR0NNIiwiYWxnIjoiUlNBLU9BRVAifQ.Kw5PHADCCpBw63G-QwHuMK75gXlZzC_RJY1SH-7ABWvmnb1KWaDCtYWbNMl-4E-dlez-LKxCbATyCFo_1WKyJcRekue7YwmfSw-eYVNOYKi2al_7-xxY8vcfxnVnyIlCetGHOJPVgeDDXr1vjbdLgg2cJhO1lRi6mDypSHqKJtyhbAR3_AYdjELPMPIMQcMdsMHa9YF5vSqoj6DnB_Bc6oLFS2fSJPki5-Gq-raWUlfnGOXEMVTm3wZGyw13extRu-H8_b6YmarvQU2oSewhWwrF3fQMzCaTUNU_yxqA6x_oZrhEeTb_BL9Q6R1oYGEXBTVQhgzWMaVRD-HtkibFjQ.Vj-fCJQPordV5AMu.RQF0cTahIAY2a-1Nr68-XyghJn9piA.8KOygvGfOdn5Wr-u-EP9bQ",
            id="alg: RSA-OAEP, enc: A192GCM"
        ),
        pytest.param(
            b"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.kINITl6EJC8SY4Y8jejN1lnuwUeENgXUmYMS_wb2rcMga63pDieYdbm-ENlsFnFIC8ANukR_lx5TIhULJAVtPHFqN2Yyb8sOuG6JKX76E6DuBj1RdS6ejpVMBNNsiNYXYxvjsVnHMyBCE48zur9sZGFaHa3Sw-_Nnesm0ygo96AuTTnz6L-mzdpPK-EhWsA1fGaR0g0EpGyEjMh6NGp6n4BRqIbeSSOOwVW39akcnSs5Wl3gZq0tN0kArq_0dN4i-Yuqm30F65MQrTn7-nnjQCoXGkzlPlU9Ex-jWtkbqqjrHqJy-Gp_AVY24PRL7a_N5AHr1WHrcrkLdZEHmjGRMA.g0_LDNNkHJ7hUjGe.WwVpEFWAZ0GXhk2YhysMS9UMBs-yfQ.fTSHPmG68YG7VHIy0-r8vQ",
            id="alg: RSA-OAEP, enc: A256GCM"
        ),
        pytest.param(
            b"eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.K6cguIsijzwwak3cqBzKlTb3izuWdFDrvClKDscxuPCfSy_dEH-WMalroPtf8sLdEa1ocrZF7udDQk6_uhD3BGy4pytFvkIy8H9jw2o7bYGU7M2qvm7CKrAE2rxk-CU4CRZItF9PWIdKxKSdvMd2lojVgLuiQKPu0EvZFW4OeV4X77Fy-0b9PcGkbkJ9iehKHk9yjqGJAGMiyTOse7_-cyXgLMJgiSKQWPfAgHYGPN39PbH_cPjxGsl4WwawmUxnEmcQ2ctVrtfvbieupGpL9LkHXIf3I08LXh8hbYGKksWeZOBDhmtKWoAnP7PrjRNeAHIag4NqTlnA8ZXx7dtS2g.uU6nyQdGTAvfbNijkodnfQ.02Bukf1CnQWB_jYUDFSooXGzqDXW0QyKvIzE-slzQtw.Tu7u7yN8HPlS7oHmmc-OQQ",
            id="alg: RSA-OAEP-256, enc: A128CBC-HS256"
        ),
        pytest.param(
            b"eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0.AKPATE5ww9Lcpbmo7OSA3ulVO4Y17mni5sYyLoc4Lvj6Wn9bHuzhFLyPA16qDDJsNE5pXxC5wemuAQugXQReeU_nSPsFYE_D7tUR4jMCrFZHMUshq0Cml7bgc34vXtBuxSMAHu16JjFI52mZKTHjFcBqCxDHE8EKWf7EdaPZf06swWKeZAnOAaRh2i9wVMzmpCJ9cFCYv0T31FTkr2XG1ydgZP2TAnMevRuTvtZ6e5xsc6lq0IH4nQCqKp6Hnb8aaoiKKbQMHNWAcmJzWYBpM2Sesv6zvzkacASMjwvx301dQKFVWV5x8Ocx2klcPFNdIgevWyT0-mLbbxgVAWFiaw.aoWEVUUMXkE7jbBBlG6UTg.fQmbAROAo1D6DHczAX3MH_eJfvRVHveJt6po1_jRud0.JSuCoAEXq4JUbZYYlGSqXd70QSr8V0U3",
            id="alg: RSA-OAEP-256, enc: A192CBC-HS384"
        ),
        pytest.param(
            b"eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0.nYIo9bUQgrQlnANR1IQI7EKPU75R2AoJR_44xXr5fEjEf444ucNbQvarO6HN5R_LQMEb0If7b8VyViMku1LuuFhYAoIfToT6SCcUgWG4vhN8mdc2Y4YsGqyF4k1c_EbQ3Gka_O04VZyhqukwpKUr89ASzqyJCWoP3kdiVfdjIkFnA_ApKGhnn2AwCy9_y8gW5TIVddYcOrQNVJtmxUWTgw6AxJSJkQztNfny6rbWdygXdeBXq7T4uAZYDquniE_h8f46SEUBb9UuMCq4eKVJZYJfPrKBVBMY9vncm-HAhl_IHzegLSJMgBWq_-idGMooxAypDg_Zi51zCpxinyrKeg.BiZjLouM-sJOpTprqKNVWw.0zL9BEdBAglQ-DQ2pBjJrRFsUt7qugRp3_nOY-sr75c.mcUVI1GvddAtqDMzElYzshrtS1GgnrUCb5brd2qzBlM",
            id="alg: RSA-OAEP-256, enc: A256CBC-HS512"
        ),
        pytest.param(
            b"eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4R0NNIn0.I8HnspRs9CiFyDyumZm5YthOVLl8Vn1unThm_EQd5YGcn0WPqXtrKeAWoP4rfOn7XaRNYeuLowpHEl-CzCjoEPEW-vui-t-P1JbDH6_wGwbdVIppdcwS6Npyv5qCNI21gPBDUB2twytEGqaYGKbbexxS8iE9iU4C_Wp-42axvUKEpxxNlQn-gPmHt4ZuzMGbI9Rl5wzT583SgmHwqXTklVC02aWQY2xQYelq5IVK-UBQ8J_NOBy7SeNeuAtmh7YxLGucSVlTqmzHImkOxsDU2UEiGJK-u8eGrgawx7DFSTUx8KXeMpsF2qe87PZhkSthpaqLFj1ZFQmVycnsN28IFg.C2qD0Dpiu2xWiDKj.o5WfgRbXOMzosaKtFCKpRyZ3nHJqLA.l8iOYFrtzGgd_x8ToB5d7w",
            id="alg: RSA-OAEP-256, enc: A128GCM"
        ),
        pytest.param(
            b"eyJlbmMiOiJBMTkyR0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.f6ynrZWg8-lerNxAa5_i7S1KUmxMD7-d_DvpBEuSgH6GmOu8jkAiZDNdiX8EcsXGrRiZKNa0So92uRLRZNQ-gb9DAs8HCiXxERYkxN4EMjWlCq8T5gLQunIC-DIotde8deZFNnechKXmrO48VTPbfb8DyAwtXPtWJUBptldghCLXP63kwLpcQKKMNcAw_E1rAT6mJAiTnk3bOfKOZqdCIpwFfCPoPE-Ign_nmh2TlDX8VFkC2ZaT-CEwiQYhjmDrm6a9S3OEIfeKF-rkiGxPnrQCN3lZN2kCM5V2Wa98zmEYd1Ce-RuxB9GKAd4RUpoF84UtBUN9sGdNSasaTLzhHg.yQfUDlEQ88R6NCTm.sverha5tzKHC1T02_9WnJnt1pCmxDg.dxi-5Nz1-9u8becvm-z0EA",
            id="alg: RSA-OAEP-256, enc: A192GCM"
        ),
        pytest.param(
            b"eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.G0e3bfJXhYxHn-rnj0FgMd4obOFIg2DTNDKrgDLN_q7KCDYd4jmABFRNIDg_hjdHEMn8xxPhzXVFyNEGvuMPQtc9Eg6WUFdbMwwuEP3VEmTXz6qbE0E-yVC6SfUQxwbyf7jnx_bDuyKd67LaOLd7K6CyiBm7NYlFHNvGAXVEEsizCBSuGbGhoHLVOuQ0IFaW8qLyaMqLfoiwZpTajwTC_t3kyAK-WyD7lhPbUoNQd8Xuj5xEoAXxCqi_LVPgVRGaM9vV-EXERJfTrLt9D6NNbh6DpqDy4jvJpwqXGu58SQUe53gRxviPNvAhm6dWz8xiQ0VlI6fgu8QUc8hRi-f1aQ.A7LLQLgEoU32zDF-.5KvzCLZD6buklVSzHiJf0IlL6zU_Zg.3hs8tmElT4SpfCRhcAtHNA",
            id="alg: RSA-OAEP-256, enc: A256GCM"
        ),
    )

    JWE_128_BIT_OCT_PACKAGES = (
        pytest.param(
            b"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiQTEyOEtXIn0.n24LSLkqXdWX4YIaOj9dwlF-1t7hTytKdO5hqg3dQ24S6kIATishhA.JpEb2cELXXsKg8A2mIiZcQ.lbEuxBQPOy0osKUSjq_evT4GWB8U9EajBoe4HVLYb-U.9MTdcq_2zePAwKWdt2ORxQ",
            id="alg: A128KW, enc: A128CBC-HS256"
        ),
        pytest.param(
            b"eyJlbmMiOiJBMTkyQ0JDLUhTMzg0IiwiYWxnIjoiQTEyOEtXIn0.RxCzQYdCBk5KR89bLFaxXnMI02b2XjHll_fIALg92FDdvmBj84kMKRs3CYszqcLsEC5pZGji_cs.qItxFbHqLvUOU9-_kOldpQ.GEY1cC2jX2AZH5fBSr9JAuTNjL75oXLg_y_f5k5qrpI.dbx5ZSyhCdsR99uz3jlzdRBqq_bWr21V",
            id="alg: A128KW, enc: A192CBC-HS384"
        ),
        pytest.param(
            b"eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYWxnIjoiQTEyOEtXIn0.ByJ5W2G8_vjD4Rl5kr6mYqiADET39cXvhhKQqTcu0OFFlBg8b5Auz1-n8LmPB-NF_4CTxd95RSn6Ykm5-CwYuRZ6plIh_VV_.YN9zjSsy0Hyq3yFR3RlKCw.9m3n0fZDmxxamWKoAvoyjCJtKJfLlc9U86tk5YgPz6Q.Mw30riFfQ7DbCe1pylfdN7XBhOnU58IG2g5i9-Stj7I",
            id="alg: A128KW, enc: A256CBC-HS512"
        ),
        pytest.param(
            b"eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiQTEyOEtXIn0.PYaHt_cEHDwdKnmYyjkCg7T1HKrAy97a.WuIrAs7jHSsXqf9A.7g_Qp6DlNVrPptVpmzFDJ_1VPljD5w.RJXqRwBMyik9V1p96r-zFQ",
            id="alg: A128KW, enc: A128GCM"
        ),
        pytest.param(
            b"eyJlbmMiOiJBMTkyR0NNIiwiYWxnIjoiQTEyOEtXIn0.4lzeEoXilgqxK5mQ4_hLBLEygUe8bVhVTKjZ9pKPezw.Xf0HU0KkMCXEjeau.vnK_Ec_lnrxENj0tE-eLyPX3UO3vrg.vjIWpB_TtA73v93E0I7JvQ",
            id="alg: A128KW, enc: A192GCM"
        ),
        pytest.param(
            b"eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiQTEyOEtXIn0.3PhAqtq7SE0CHpuhVhEViywAOn-w55vBvN1iGWKCn3-nioam-h-GIQ.4maA1p_t7_peTBZM.r60jOf8J5Y7lkFc8xBxtNl9yoC6jZA.SWPFQWHjLMzj0pq2CHJUBA",
            id="alg: A128KW, enc: A256GCM"
        ),
    )

    JWE_192_BIT_OCT_PACKAGES = (
        pytest.param(
            b"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiQTE5MktXIn0.RAXHkAPR_VsfFC5JAB0j24t_GdWa9udWTZZ_L18KE-qi9Au95oK-VA.J4YETSJp_EuV4AP0tWGIpw.VktlsPA1yF51IDXVtkrkmgHqPahz5-MjwAjCP0j3_EA.5h57BdovPem9fmyx-UcURA",
            id="alg: A192KW, enc: A128CBC-HS256"
        ),
        pytest.param(
            b"eyJlbmMiOiJBMTkyQ0JDLUhTMzg0IiwiYWxnIjoiQTE5MktXIn0.Z2AmR2Y6viywyGDPPO92V5MJCwfULSRGmeSjV4VHqEnVyUE-AJhKety8Kw5dS_ydWVpZ0IGe4S0.Ny9jR93JsAigFdJXrcb1hQ.jwvtxfGZC3O6P8lBFUSb5OTRLFVje6Fo1H0X5F4uv1w.p14y3-XZHA3FiFSvXdbTsaFkylbwIKn3",
            id="alg: A192KW, enc: A192CBC-HS384"
        ),
        pytest.param(
            b"eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYWxnIjoiQTE5MktXIn0.wWChMcIkEaDfoMNfgsG1pomBzef0PYx_dJIe4V4JWeCS8RhH6_IzUb-zsgvyDUtKGeUHcwwQ66mpKnQO27-5p7cv6Geho9mq.5PcNZjsulZ3fTLu_NlQF2g.lXibtdYC3GsIiEtzkHqnOKu5uPrp6Fs8cdrakjZzQ4E.EuxTWElqFsG3lF4iJSGlzQKb3NXppEWQhWcpMOepjJE",
            id="alg: A192KW, enc: A256CBC-HS512"
        ),
        pytest.param(
            b"eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiQTE5MktXIn0.acwCCSF6htimS4JReQVQii4RDwq9HD5a.JMdpDaFlJMMjm_Cz.tEkn2o4ngBafL16ldPcdR0VWhphi2w.3GpPpXKYtbPKzE6kTLtKEA",
            id="alg: A192KW, enc: A128GCM"
        ),
        pytest.param(
            b"eyJlbmMiOiJBMTkyR0NNIiwiYWxnIjoiQTE5MktXIn0.wXPSpLsBCaM0pBe9bFgUz-W0FLyAmGeRBI_VWD19rmU.XoiqwULpsnNvhwNo.sB3yhTbfBfWo7nbz8ZzLMX-RKzvrQw.Dn4XlsQpEjrf3mrjQ7sT5Q",
            id="alg: A192KW, enc: A192GCM"
        ),
        pytest.param(
            b"eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiQTE5MktXIn0.DlGLalCXypefklVSenCRDRocRhHd3OI5vuAsxqTdDuVAks4PGbSkdw.zKpteENM-uElbKXK.cGvn4ozoLauLx-d7oEMJaLu-LttauA.1XOWJ6jZaxHWG13MUSPRAQ",
            id="alg: A192KW, enc: A256GCM"
        ),
    )

    JWE_256_BIT_OCT_PACKAGES = (
        pytest.param(
            b"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiQTI1NktXIn0.XoNzh3DeJkShGkoZUlIHN6OHiA7ku5WzI_e9HvddWf-W6ygXfjiS8g.qUSQp7nyMReRRgGfw_VYmg.rrsoeZ_IecEkOAwOLyXWAo8uATnevhQJnIG4Gs-xUX8.05BaSh2pSaowV2omCOUdrw",
            id="alg: A256KW, enc: A128CBC-HS256"
        ),
        pytest.param(
            b"eyJlbmMiOiJBMTkyQ0JDLUhTMzg0IiwiYWxnIjoiQTI1NktXIn0.b2-ui_1ksCzR28fUnBqtfwhKJZxklXboiN6AkhiDlOuj54lrn5CcHCjOOj_p5TwYWrFIEV3cQqw.zZqUrF5ygGZ27kPqWsx1bg.qAgz0LaznF_uyh4k37DesB0k5im-GwC9Au7l0dXVdhI.guaip_HKbIHbKZJCVXSKjcNv40w5aYZQ",
            id="alg: A256KW, enc: A192CBC-HS384"
        ),
        pytest.param(
            b"eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYWxnIjoiQTI1NktXIn0.325MvraC58qFxXdD1gjRMwM_1NTW1-517eOckhcWuDUeAEUm6AHM9y1UsyC3StCDgFzDWbIZe3fayLh7OqVilr31gdofBWI9.hN1R-yoBJzALfcVFUvdKkQ.n-bQyooo7ufWn1CETJ8YFy9BFGWNgggrgoDlhmGI_Y8.6VyiR7w1osq6T8_rR-BAvyKAWAQSSA3oEc4jOPO7iJw",
            id="alg: A256KW, enc: A256CBC-HS512"
        ),
        pytest.param(
            b"eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiQTI1NktXIn0.d4wqGBFQG-MrzDgbWWB23o9LUgCkaTYt.NkFLhQfcR2swvLT3.lrt2LS9nrUqB9BDahJLqR-DZxutraA.MbghLfohCD71xfX8lRpVAw",
            id="alg: A256KW, enc: A128GCM"
        ),
        pytest.param(
            b"eyJlbmMiOiJBMTkyR0NNIiwiYWxnIjoiQTI1NktXIn0.XhgSqN16cCtwttRTxRXJfYx6FL9c56Bjo6VQx8E6vGI.C--W8_faFWiCxTCM.ZyTZRiqdLEMOnwQytgAujl-t6nZ-ZQ.GqyRs7YnGsGlwUehCXmllA",
            id="alg: A256KW, enc: A192GCM"
        ),
        pytest.param(
            b"eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiQTI1NktXIn0.i_-ehDezyG89YFcWqU-MxPB1HtVHauEAUGInnjlodx44IJBLS4ap4Q.nCEooStwaMWLfDxt.lqjEVnCRHCaufTIcxT2MzeBwUE2V-Q.sIr7c2QlWIYSVwnXUHgITA",
            id="alg: A256KW, enc: A256GCM"
        ),
    )

    @pytest.mark.parametrize("jwe_package", JWE_RSA_PACKAGES)
    def test_decrypt_rsa_key_wrap(self, jwe_package):
        headers = jwe.get_unverified_header(jwe_package)
        if headers["alg"] not in ALGORITHMS.SUPPORTED:
            pytest.skip("alg {} not supported".format(headers["alg"]))
        if headers["enc"] not in ALGORITHMS.SUPPORTED:
            pytest.skip("enc {} not supported".format(headers["enc"]))
        key = PRIVATE_KEY_PEM
        actual = jwe.decrypt(jwe_package, key)
        assert actual == "Live long and prosper."

    @pytest.mark.parametrize("jwe_package", JWE_128_BIT_OCT_PACKAGES)
    def test_decrypt_oct_128_key_wrap(self, jwe_package):
        key = OCT_128_BIT_KEY
        headers = jwe.get_unverified_header(jwe_package)
        if headers["alg"] not in ALGORITHMS.SUPPORTED:
            pytest.skip("alg {} not supported".format(headers["alg"]))
        if headers["enc"] not in ALGORITHMS.SUPPORTED:
            pytest.skip("enc {} not supported".format(headers["enc"]))
        actual = jwe.decrypt(jwe_package, key)
        assert actual == "Live long and prosper."

    @pytest.mark.parametrize("jwe_package", JWE_192_BIT_OCT_PACKAGES)
    def test_decrypt_oct_192_key_wrap(self, jwe_package):
        headers = jwe.get_unverified_header(jwe_package)
        if headers["alg"] not in ALGORITHMS.SUPPORTED:
            pytest.skip("alg {} not supported".format(headers["alg"]))
        if headers["enc"] not in ALGORITHMS.SUPPORTED:
            pytest.skip("enc {} not supported".format(headers["enc"]))
        key = OCT_192_BIT_KEY
        actual = jwe.decrypt(jwe_package, key)
        assert actual == "Live long and prosper."

    @pytest.mark.parametrize("jwe_package", JWE_256_BIT_OCT_PACKAGES)
    def test_decrypt_oct_256_key_wrap(self, jwe_package):
        headers = jwe.get_unverified_header(jwe_package)
        if headers["alg"] not in ALGORITHMS.SUPPORTED:
            pytest.skip("alg {} not supported".format(headers["alg"]))
        if headers["enc"] not in ALGORITHMS.SUPPORTED:
            pytest.skip("enc {} not supported".format(headers["enc"]))
        key = OCT_256_BIT_KEY
        actual = jwe.decrypt(jwe_package, key)
        assert actual == "Live long and prosper."

    def test_invalid_jwe_is_parse_error(self):
        with pytest.raises(JWEParseError):
            jwe.decrypt("invalid", "key")

    def test_non_json_header_is_parse_error(self):
        jwe_str = "ciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." \
                  "UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7" \
                  "Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgN" \
                  "Z__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRir" \
                  "b6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8" \
                  "OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0m" \
                  "cKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A" \
                  "." \
                  "AxY8DCtDaGlsbGljb3RoZQ." \
                  "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY." \
                  "9hH0vgRfYgPnAHOd8stkvw"
        with pytest.raises(JWEParseError):
            jwe.decrypt(jwe_str, "key")


class TestEncrypt(object):

    @pytest.mark.skipif(AESKey is None, reason="No AES backend")
    def test_rfc7516_appendix_b_direct(self, monkeypatch):
        algorithm = ALGORITHMS.DIR
        encryption = ALGORITHMS.A128CBC_HS256
        key = bytes(bytearray(
            [4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170,
             106, 206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240,
             143, 156, 44, 207]
        ))
        plain_text = b"Live long and prosper."
        expected_iv = bytes(bytearray([3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111,
                                       116, 104, 101]))

        for backend in backends:
            monkeypatch.setattr(backend, "get_random_bytes", lambda x: expected_iv if x == 16 else key)

        expected = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.BIiCkt8mWOVyJOqDMwNqaQ"
        actual = jwe.encrypt(plain_text, key, encryption, algorithm)

        assert actual == expected

    @pytest.mark.skipif(AESKey is None, reason="No AES backend")
    @pytest.mark.parametrize("alg", filter(lambda x: x in ALGORITHMS.SUPPORTED, ALGORITHMS.RSA_KW))
    @pytest.mark.parametrize("enc", filter(lambda x: x in ALGORITHMS.SUPPORTED, ALGORITHMS.AES_ENC))
    @pytest.mark.parametrize("zip", ZIPS.SUPPORTED)
    def test_encrypt_decrypt_rsa_kw(self, alg, enc, zip):
        expected = "Live long and prosper."
        jwe_value = jwe.encrypt(expected[:], PUBLIC_KEY_PEM, enc, alg, zip)
        actual = jwe.decrypt(jwe_value, PRIVATE_KEY_PEM)
        assert actual == expected

    @pytest.mark.skipif(AESKey is None, reason="No AES backend")
    @pytest.mark.parametrize("alg", ALGORITHMS.AES_KW)
    @pytest.mark.parametrize("enc", filter(lambda x: x in ALGORITHMS.SUPPORTED, ALGORITHMS.AES_ENC))
    @pytest.mark.parametrize("zip", ZIPS.SUPPORTED)
    def test_encrypt_decrypt_aes_kw(self, alg, enc, zip):
        if alg == ALGORITHMS.A128KW:
            key = OCT_128_BIT_KEY
        elif alg == ALGORITHMS.A192KW:
            key = OCT_192_BIT_KEY
        elif alg == ALGORITHMS.A256KW:
            key = OCT_256_BIT_KEY
        else:
            pytest.fail("I don't know how to handle enc {}".format(alg))
        expected = "Live long and prosper."
        jwe_value = jwe.encrypt(expected[:], key, enc, alg, zip)
        actual = jwe.decrypt(jwe_value, key)
        assert actual == expected

    @pytest.mark.skipif(AESKey is None, reason="No AES backend")
    @pytest.mark.parametrize("enc", filter(lambda x: x in ALGORITHMS.SUPPORTED, ALGORITHMS.AES_ENC))
    @pytest.mark.parametrize("zip", ZIPS.SUPPORTED)
    def test_encrypt_decrypt_dir_kw(self, enc, zip):
        if enc == ALGORITHMS.A128GCM:
            key = OCT_128_BIT_KEY
        elif enc == ALGORITHMS.A192GCM:
            key = OCT_192_BIT_KEY
        elif enc in (ALGORITHMS.A128CBC_HS256, ALGORITHMS.A256GCM):
            key = OCT_256_BIT_KEY
        elif enc == ALGORITHMS.A192CBC_HS384:
            key = OCT_384_BIT_KEY
        elif enc == ALGORITHMS.A256CBC_HS512:
            key = OCT_512_BIT_KEY
        else:
            pytest.fail("I don't know how to handle enc {}".format(enc))
        expected = "Live long and prosper."
        jwe_value = jwe.encrypt(expected[:], key, enc, ALGORITHMS.DIR, zip)
        actual = jwe.decrypt(jwe_value, key)
        assert actual == expected

    @pytest.mark.skipif(AESKey is None, reason="No AES backend")
    def test_alg_enc_headers(self):
        enc = ALGORITHMS.A256CBC_HS512
        alg = ALGORITHMS.RSA_OAEP_256
        encrypted = jwe.encrypt("Text", PUBLIC_KEY_PEM, enc, alg)
        header = json.loads(six.ensure_str(base64url_decode(encrypted.split(".")[0])))
        assert header["enc"] == enc
        assert header["alg"] == alg

    @pytest.mark.skipif(AESKey is None, reason="No AES backend")
    def test_cty_header_present_when_provided(self):
        enc = ALGORITHMS.A256CBC_HS512
        alg = ALGORITHMS.RSA_OAEP_256
        encrypted = jwe.encrypt("Text", PUBLIC_KEY_PEM, enc, alg,
                                cty="expected")
        header = json.loads(six.ensure_str(base64url_decode(encrypted.split(".")[0])))
        assert header["cty"] == "expected"

    @pytest.mark.skipif(AESKey is None, reason="No AES backend")
    def test_cty_header_not_present_when_not_provided(self):
        enc = ALGORITHMS.A256CBC_HS512
        alg = ALGORITHMS.RSA_OAEP_256
        encrypted = jwe.encrypt("Text", PUBLIC_KEY_PEM, enc, alg)
        header = json.loads(six.ensure_str(base64url_decode(encrypted.split(".")[0])))
        assert "cty" not in header

    @pytest.mark.skipif(AESKey is None, reason="No AES backend")
    def test_zip_header_present_when_provided(self):
        enc = ALGORITHMS.A256CBC_HS512
        alg = ALGORITHMS.RSA_OAEP_256
        encrypted = jwe.encrypt("Text", PUBLIC_KEY_PEM, enc, alg,
                                zip=ZIPS.DEF)
        header = json.loads(six.ensure_str(base64url_decode(encrypted.split(".")[0])))
        assert header["zip"] == ZIPS.DEF

    @pytest.mark.skipif(AESKey is None, reason="No AES backend")
    def test_zip_header_not_present_when_not_provided(self):
        enc = ALGORITHMS.A256CBC_HS512
        alg = ALGORITHMS.RSA_OAEP_256
        encrypted = jwe.encrypt("Text", PUBLIC_KEY_PEM, enc, alg)
        header = json.loads(six.ensure_str(base64url_decode(encrypted.split(".")[0])))
        assert "zip" not in header

    @pytest.mark.skipif(AESKey is None, reason="No AES backend")
    def test_zip_header_not_present_when_none(self):
        enc = ALGORITHMS.A256CBC_HS512
        alg = ALGORITHMS.RSA_OAEP_256
        encrypted = jwe.encrypt("Text", PUBLIC_KEY_PEM, enc, alg,
                                zip=ZIPS.NONE)
        header = json.loads(six.ensure_str(base64url_decode(encrypted.split(".")[0])))
        assert "zip" not in header

    @pytest.mark.skipif(AESKey is None, reason="No AES backend")
    def test_kid_header_present_when_provided(self):
        enc = ALGORITHMS.A256CBC_HS512
        alg = ALGORITHMS.RSA_OAEP_256
        encrypted = jwe.encrypt("Text", PUBLIC_KEY_PEM, enc, alg,
                                kid="expected")
        header = json.loads(six.ensure_str(base64url_decode(encrypted.split(".")[0])))
        assert header["kid"] == "expected"

    @pytest.mark.skipif(AESKey is None, reason="No AES backend")
    def test_kid_header_not_present_when_not_provided(self):
        enc = ALGORITHMS.A256CBC_HS512
        alg = ALGORITHMS.RSA_OAEP_256
        encrypted = jwe.encrypt("Text", PUBLIC_KEY_PEM, enc, alg)
        header = json.loads(six.ensure_str(base64url_decode(encrypted.split(".")[0])))
        assert "kid" not in header
