"""POST /v1/recall/check-signed 的端到端测试。"""

import base64
import json

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app import signed

client = TestClient(app)

FNC1 = "\x1d"  # ASCII 29

ENDPOINT = "/v1/recall/check-signed"


def make_gtin(body13: str) -> str:
    """由 13 位本体计算模 10 校验位,生成合法 14 位 GTIN。"""
    assert len(body13) == 13 and body13.isdigit()
    total = sum(int(c) * (3 if i % 2 == 0 else 1) for i, c in enumerate(reversed(body13)))
    return body13 + str((10 - total % 10) % 10)


GTIN = make_gtin("0950600112345")
GTIN2 = make_gtin("0950600112346")
OTHER_GTIN = make_gtin("0880000000001")

NOW = 1_780_000_000  # 固定核验时刻
KID = "test-key-1"
PREFIXES = ["0950600"]


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@pytest.fixture
def signer(tmp_path, monkeypatch):
    """生成临时密钥并把信任文件指向 tmp_path;返回一个 compact JWS 签名器。"""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.generate()
    pub_raw = priv.public_key().public_bytes_raw()
    trust_path = tmp_path / "trust.json"
    trust_path.write_text(
        json.dumps(
            {"keys": [{"kid": KID, "public_key": b64url(pub_raw), "gtin_prefixes": PREFIXES}]}
        )
    )
    monkeypatch.setenv(signed.TRUST_FILE_ENV, str(trust_path))
    signed.reset_trust_cache()

    def make(
        payload: dict | None = None,
        *,
        kid: str = KID,
        alg: str = "EdDSA",
        header_extra: dict | None = None,
        raw_header: dict | None = None,
        tamper: bool = False,
    ) -> str:
        header = raw_header if raw_header is not None else {"alg": alg, "kid": kid}
        if header_extra:
            header = {**header, **header_extra}
        body = payload if payload is not None else {
            "nbf": NOW - 10,
            "exp": NOW + 10,
            "rules": [{"id": "R1", "gtin": GTIN}],
        }
        h = b64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
        p = b64url(json.dumps(body, separators=(",", ":"), sort_keys=True).encode())
        signing_input = f"{h}.{p}".encode()
        sig = priv.sign(signing_input)
        if tamper:
            sig = bytes([sig[0] ^ 0xFF]) + sig[1:]
        return f"{h}.{p}.{b64url(sig)}"

    yield make

    signed.reset_trust_cache()


def post(jws: str, now: int = NOW, scans=None):
    scans = scans if scans is not None else ["01" + GTIN]
    return client.post(ENDPOINT, json={"scans": scans, "jws": jws, "now": now})


def rule(rid="R1", gtin=GTIN, **kw):
    return {"id": rid, "gtin": gtin, **kw}


# ---------- 正常路径 ----------


def test_signed_check_ok(signer):
    jws = signer({"nbf": NOW - 10, "exp": NOW + 10, "rules": [rule()]})
    resp = post(jws, scans=["01" + GTIN + "10" + "LOT1"])
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["kid"] == KID
    (result,) = data["results"]
    assert result["ok"] is True
    assert result["fields"]["gtin"] == GTIN
    assert result["matches"] == ["R1"]


def test_signed_check_bad_scan_does_not_fail_request(signer):
    jws = signer({"nbf": NOW - 10, "exp": NOW + 10, "rules": [rule()]})
    resp = post(jws, scans=["01" + GTIN, "01" + GTIN + "99"])
    assert resp.status_code == 200, resp.text
    results = resp.json()["results"]
    assert [r["ok"] for r in results] == [True, False]
    assert results[0]["matches"] == ["R1"]
    assert results[1]["matches"] == []
    assert "未知 AI" in results[1]["error"]["reason"]


def test_multiple_rules_and_matches_order(signer):
    payload = {
        "nbf": NOW,
        "exp": NOW + 10,
        "rules": [rule("R-last", batch="LOT1"), rule("R-first")],
    }
    resp = post(signer(payload), scans=["01" + GTIN + "10" + "LOT1"])
    assert resp.status_code == 200, resp.text
    assert resp.json()["results"][0]["matches"] == ["R-last", "R-first"]


def test_nbf_boundary_inclusive_exp_exclusive(signer):
    scan = ["01" + GTIN]
    # now == nbf:通过
    resp = post(signer({"nbf": NOW, "exp": NOW + 1, "rules": [rule()]}), now=NOW, scans=scan)
    assert resp.status_code == 200, resp.text
    # now == exp:拒绝(右开区间)
    resp = post(signer({"nbf": NOW - 1, "exp": NOW, "rules": [rule()]}), now=NOW, scans=scan)
    assert resp.status_code == 403, resp.text
    assert "有效期" in resp.json()["detail"]
    # now < nbf:拒绝
    resp = post(signer({"nbf": NOW + 1, "exp": NOW + 2, "rules": [rule()]}), scans=scan)
    assert resp.status_code == 403, resp.text


# ---------- 403:签名 / 密钥 / 越权 ----------


def test_tampered_signature_is_403(signer):
    resp = post(signer(tamper=True))
    assert resp.status_code == 403, resp.text
    assert "签名" in resp.json()["detail"]
    assert "results" not in resp.json()


def test_tampered_payload_is_403(signer):
    jws = signer()
    head, _payload, sig = jws.split(".")
    forged_payload = b64url(
        json.dumps(
            {"nbf": NOW - 10, "exp": NOW + 10, "rules": [rule(gtin=OTHER_GTIN)]},
            separators=(",", ":"),
        ).encode()
    )
    resp = post(f"{head}.{forged_payload}.{sig}")
    assert resp.status_code == 403
    assert "签名" in resp.json()["detail"]


def test_unknown_kid_is_403(signer):
    resp = post(signer(kid="no-such-kid"))
    assert resp.status_code == 403, resp.text
    assert "未知密钥" in resp.json()["detail"]


def test_unauthorized_gtin_prefix_is_403(signer):
    payload = {"nbf": NOW - 10, "exp": NOW + 10, "rules": [rule(gtin=OTHER_GTIN)]}
    resp = post(signer(payload))
    assert resp.status_code == 403, resp.text
    assert "授权" in resp.json()["detail"]
    assert "results" not in resp.json()


def test_every_rule_must_match_a_prefix(signer):
    # 两条规则,一条授权一条越权:整体 403
    payload = {
        "nbf": NOW - 10,
        "exp": NOW + 10,
        "rules": [rule("ok"), rule("bad", gtin=OTHER_GTIN)],
    }
    resp = post(signer(payload))
    assert resp.status_code == 403


def test_expired_is_403(signer):
    resp = post(signer({"nbf": NOW - 100, "exp": NOW - 1, "rules": [rule()]}))
    assert resp.status_code == 403


# ---------- 422:JWS 与载荷格式 ----------


def test_malformed_compact_serialization_422(signer):
    for bad in ["a.b", "a.b.c.d", ".a.b", "a..b", "abc"]:
        resp = post(bad)
        assert resp.status_code == 422, (bad, resp.text)
        assert "三段" in resp.json()["detail"]


def test_non_base64url_segment_422(signer):
    jws = signer()
    head, payload, sig = jws.split(".")
    # 含填充 '='
    resp = post(f"{head}.{payload}.{sig}==")
    assert resp.status_code == 422
    # 含空白 / '+' / '/'
    resp = post(f"{head}.{payload}.{sig[:-1]} +")
    assert resp.status_code == 422


def test_header_alg_must_be_eddsa_422(signer):
    resp = post(signer(alg="ES256"))
    assert resp.status_code == 422
    assert "alg" in resp.json()["detail"]


def test_header_extra_or_missing_field_422(signer):
    # 多余字段
    resp = post(signer(header_extra={"typ": "JWT"}))
    assert resp.status_code == 422
    # 缺 kid
    resp = post(signer(raw_header={"alg": "EdDSA"}))
    assert resp.status_code == 422


def test_header_duplicate_json_key_422(signer):
    # 手工构造含重复键的头部 JSON
    head = b64url(b'{"alg":"EdDSA","kid":"' + KID.encode() + b'","kid":"x"}')
    payload = b64url(b'{"nbf":0,"exp":1,"rules":[]}')
    resp = post(f"{head}.{payload}.xxx")
    assert resp.status_code == 422
    assert "重复键" in resp.json()["detail"]


def test_payload_wrong_shape_422(signer):
    # 多余字段
    resp = post(signer({"nbf": 0, "exp": 1, "rules": [rule()], "iss": "x"}))
    assert resp.status_code == 422
    # 缺字段
    resp = post(signer({"nbf": 0, "exp": 1}))
    assert resp.status_code == 422
    # 顶层非对象
    jws = signer()
    head, _p, sig = jws.split(".")
    p = b64url(b"[1,2,3]")
    resp = post(f"{head}.{p}.{sig}")
    assert resp.status_code == 422


def test_nbf_exp_must_be_integers_422(signer):
    for nbf, exp in [("1", 2), (1, 2.0), (True, 2), (1, None)]:
        resp = post(signer({"nbf": nbf, "exp": exp, "rules": [rule()]}))
        assert resp.status_code == 422, (nbf, exp, resp.text)


def test_rules_empty_422(signer):
    resp = post(signer({"nbf": 0, "exp": NOW + 10, "rules": []}))
    assert resp.status_code == 422


def test_invalid_rule_shape_422(signer):
    # GTIN 校验位错误
    bad_gtin = GTIN[:-1] + str((int(GTIN[-1]) + 1) % 10)
    resp = post(signer({"nbf": 0, "exp": NOW + 10, "rules": [rule(gtin=bad_gtin)]}))
    assert resp.status_code == 422
    assert "rules[0]" in resp.json()["detail"]
    # 多余字段
    resp = post(
        signer({"nbf": 0, "exp": NOW + 10, "rules": [dict(rule(), bogus=1)]})
    )
    assert resp.status_code == 422
    # 日期区间倒置
    resp = post(
        signer(
            {
                "nbf": 0,
                "exp": NOW + 10,
                "rules": [rule(date_from="2026-01-01", date_to="2025-01-01")],
            }
        )
    )
    assert resp.status_code == 422
    # 规则不是对象
    resp = post(signer({"nbf": 0, "exp": NOW + 10, "rules": ["R1"]}))
    assert resp.status_code == 422


def test_duplicate_rule_id_422(signer):
    payload = {"nbf": 0, "exp": NOW + 10, "rules": [rule(), rule()]}
    resp = post(signer(payload))
    assert resp.status_code == 422


def test_invalid_rule_is_422_even_when_expired(signer):
    # 规则格式非法(422)优先于越期(403):不返回匹配结果
    bad_gtin = GTIN[:-1] + str((int(GTIN[-1]) + 1) % 10)
    payload = {"nbf": 0, "exp": NOW - 1, "rules": [rule(gtin=bad_gtin)]}
    resp = post(signer(payload))
    assert resp.status_code == 422
    assert "results" not in resp.json()


def test_duplicate_json_key_inside_rule_422(signer):
    # 规则对象里重复 id(原始 JSON,绕过 pydantic)
    raw_payload = (
        b'{"nbf":0,"exp":' + str(NOW + 10).encode() + b',"rules":['
        b'{"id":"R1","id":"R2","gtin":"' + GTIN.encode() + b'"}]}'
    )
    jws = signer()
    head, _p, sig = jws.split(".")
    resp = post(f"{head}.{b64url(raw_payload)}.{sig}")
    assert resp.status_code == 422
    assert "重复键" in resp.json()["detail"]


def test_payload_duplicate_top_level_key_422(signer):
    jws = signer()
    head, _p, sig = jws.split(".")
    raw = (
        b'{"nbf":0,"exp":' + str(NOW + 10).encode() + b',"rules":[{"id":"R1","gtin":"'
        + GTIN.encode() + b'"}],"nbf":1}'
    )
    resp = post(f"{head}.{b64url(raw)}.{sig}")
    assert resp.status_code == 422
    assert "重复键" in resp.json()["detail"]


# ---------- 422:请求体 ----------


def test_request_body_validation_422(signer):
    base = {"scans": ["01" + GTIN], "jws": signer(), "now": NOW}
    for mutation in [
        {"scans": []},
        {"scans": ["x"] * 101},
        {"jws": ""},
        {"now": True},  # bool 不得当作整数
        {"now": 1.5},
        {"now": "1780000000"},
        {"extra": 1},
    ]:
        body = {**base, **mutation}
        resp = client.post(ENDPOINT, json=body)
        assert resp.status_code == 422, (mutation, resp.text)


def test_missing_field_422(signer):
    resp = client.post(ENDPOINT, json={"scans": ["01" + GTIN], "jws": signer()})
    assert resp.status_code == 422


# ---------- 信任文件 ----------


def test_missing_trust_file_is_500(signer, monkeypatch, tmp_path):
    monkeypatch.setenv(signed.TRUST_FILE_ENV, str(tmp_path / "nope.json"))
    signed.reset_trust_cache()
    resp = post(signer())
    assert resp.status_code == 500
    assert "信任文件" in resp.json()["detail"]


def test_malformed_trust_file_is_500(signer, monkeypatch):
    import os

    path = os.environ[signed.TRUST_FILE_ENV]
    with open(path, "w") as fh:
        fh.write('{"keys": [{"kid": "x", "public_key": "!!!", "gtin_prefixes": ["1"]}]}')
    signed.reset_trust_cache()
    resp = post(signer())
    assert resp.status_code == 500
    # 修复后(缓存随文件变化刷新)又能通过
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.generate()
    good = {
        "keys": [
            {"kid": KID, "public_key": b64url(priv.public_key().public_bytes_raw()),
             "gtin_prefixes": PREFIXES}
        ]
    }
    # 用测试自己的公钥无法验证 signer 的签名,故只校验文件损坏时为 500 即可
    with open(path, "w") as fh:
        json.dump(good, fh)
    signed.reset_trust_cache()
    resp = post(signer())
    assert resp.status_code == 403  # 公钥被换:签名失败,而非 500
