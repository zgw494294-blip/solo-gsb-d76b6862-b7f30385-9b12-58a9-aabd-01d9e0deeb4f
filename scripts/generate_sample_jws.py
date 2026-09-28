#!/usr/bin/env python3
"""本地样例生成脚本:生成 Ed25519 密钥对、信任文件与 compact JWS 样例。

**仅用于本地开发 / 演示,切勿用于生产。** 默认使用固定种子(固定 32 字节),
因此重复执行生成的 trust.json 与样例密钥完全一致,便于随仓库提供可直接调用的样例。
生产环境应使用安全随机私钥(可用 ``--random-key``),私钥由签发方离线保管,
信任文件只放公钥。

用法:

    python scripts/generate_sample_jws.py                 # 生成 trust.json + 样例 JWS
    python scripts/generate_sample_jws.py --random-key    # 使用随机密钥
    python scripts/generate_sample_jws.py --now 1780000000
    python scripts/generate_sample_jws.py --ttl 3600
    python scripts/generate_sample_jws.py --kid my-key --gtin-prefix 0950600

产物:

    trust.json                 信任文件(公钥 + 授权 GTIN 前缀),--trust-file 可改路径
    examples/signed-check.json 可直接 POST 的请求体样例(jws + scans + now)

JWS 头部:{"alg": "EdDSA", "kid": ...};载荷:{"nbf", "exp", "rules"},
三段均为无填充 base64url,签名为对 "头部.载荷" 原始字节的 Ed25519 签名。
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO_ROOT = Path(__file__).resolve().parent.parent

# 固定演示种子(32 字节);仅用于本地样例,重复执行得到同一密钥
_DEMO_SEED = b"gs1-recall-demo-only-seed-32by!!"
assert len(_DEMO_SEED) == 32

DEFAULT_KID = "demo-recall-2026"
# 与 README 样例 GTIN 09506001123454 / 09506001123461 匹配
DEFAULT_PREFIXES = ["0950600"]
DEFAULT_RULE = {
    "id": "recall-2026-001",
    "gtin": "09506001123454",
    "batch": "LOT1",
    "date_from": "2025-01-01",
    "date_to": "2026-12-31",
}
DEFAULT_SCAN = "]d201095060011234541725123110LOT1\x1d21SN9"

DEFAULT_NBF = 0  # 1970-01-01:样例长期可用;真实签发请用当前时间


def b64url(data: bytes) -> str:
    """无填充 base64url 编码。"""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_private_key(random_key: bool) -> Ed25519PrivateKey:
    if random_key:
        return Ed25519PrivateKey.generate()
    return Ed25519PrivateKey.from_private_bytes(_DEMO_SEED)


def encode_public_key(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return b64url(raw)


def sign_compact_jws(private_key: Ed25519PrivateKey, kid: str, payload: dict) -> str:
    """生成 compact JWS:b64url(header).b64url(payload).b64url(signature)。"""
    header = {"alg": "EdDSA", "kid": kid}
    header_seg = b64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    payload_seg = b64url(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    signing_input = f"{header_seg}.{payload_seg}".encode("ascii")
    signature_seg = b64url(private_key.sign(signing_input))
    return f"{header_seg}.{payload_seg}.{signature_seg}"


def main() -> None:
    parser = argparse.ArgumentParser(description="生成本地签名核验样例(Ed25519 compact JWS)")
    parser.add_argument("--kid", default=DEFAULT_KID, help="密钥 ID(默认 %(default)s)")
    parser.add_argument(
        "--gtin-prefix",
        action="append",
        dest="gtin_prefixes",
        help="授权 GTIN 前缀(1~14 位数字),可重复;默认 %(default)s",
    )
    parser.add_argument(
        "--trust-file",
        default=str(REPO_ROOT / "trust.json"),
        help="信任文件输出路径(默认仓库根 trust.json)",
    )
    parser.add_argument(
        "--out",
        default=str(REPO_ROOT / "examples" / "signed-check.json"),
        help="请求体样例输出路径(默认 examples/signed-check.json)",
    )
    parser.add_argument("--now", type=int, default=None, help="当前 Unix 秒(默认取系统时间)")
    parser.add_argument("--nbf", type=int, default=None, help="nbf Unix 秒(默认 0)")
    parser.add_argument("--exp", type=int, default=None, help="exp Unix 秒(默认 now+ttl)")
    parser.add_argument("--ttl", type=int, default=10 * 365 * 24 * 3600, help="有效期秒数(默认 10 年)")
    parser.add_argument(
        "--random-key",
        action="store_true",
        help="使用安全随机密钥(默认使用固定演示种子,重复执行幂等)",
    )
    args = parser.parse_args()

    prefixes = args.gtin_prefixes or list(DEFAULT_PREFIXES)
    for prefix in prefixes:
        if not (1 <= len(prefix) <= 14) or not prefix.isdigit():
            parser.error(f"GTIN 前缀须为 1~14 位数字: {prefix!r}")

    private_key = make_private_key(args.random_key)
    public_key_b64 = encode_public_key(private_key)

    trust_path = Path(args.trust_file)
    trust_path.parent.mkdir(parents=True, exist_ok=True)
    trust_body = {
        "keys": [
            {
                "kid": args.kid,
                "public_key": public_key_b64,
                "gtin_prefixes": prefixes,
            }
        ]
    }
    trust_path.write_text(json.dumps(trust_body, ensure_ascii=False, indent=2) + "\n")

    now = args.now if args.now is not None else int(time.time())
    nbf = args.nbf if args.nbf is not None else DEFAULT_NBF
    exp = args.exp if args.exp is not None else now + args.ttl
    payload = {"nbf": nbf, "exp": exp, "rules": [DEFAULT_RULE]}
    jws = sign_compact_jws(private_key, args.kid, payload)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    body = {"scans": [DEFAULT_SCAN], "jws": jws, "now": now}
    out_path.write_text(json.dumps(body, ensure_ascii=False, indent=2) + "\n")

    print(f"信任文件已写入: {trust_path}")
    print(f"请求样例已写入: {out_path}")
    print(f"kid={args.kid} 授权 GTIN 前缀={prefixes}  nbf={nbf}  exp={exp}  now={now}")
    print()
    print("调用示例:")
    print(f"  curl -s http://localhost:8000/v1/recall/check-signed \\")
    print(f"    -H 'Content-Type: application/json' \\")
    print(f"    -d @{os.path.relpath(out_path)}")
    print()
    if not args.random_key:
        print("注意: 当前使用固定演示种子,仅限本地开发;生产请加 --random-key 并妥善保管私钥。")


if __name__ == "__main__":
    main()
