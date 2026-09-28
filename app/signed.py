"""签名召回核验:compact JWS (Ed25519) 解析、本地信任文件查询与授权校验。

JWS 三段均为**无填充 base64url**;头部仅含 ``alg=EdDSA`` 与非空 ``kid``,
载荷仅含整数 ``nbf`` / ``exp`` 与现有格式 ``rules``。

- 任意层 JSON 重复键(含规则内部)一律按格式非法拒绝。
- 签名以原始前两段(含中间的点)为 signing input,用信任文件中 kid 对应的
  Ed25519 公钥验证;公钥只从本地信任文件读取,不联网取钥。
- 须满足 ``nbf <= now < exp``,且每条规则的 14 位 GTIN 至少匹配该 kid
  授权的一个 GTIN 前缀(1~14 位数字,前缀比较)。

格式问题抛 :class:`SignedFormatError`(路由层映射 422);未知密钥、签名失败、
越期、越权抛 :class:`SignedForbiddenError`(映射 403);信任文件本身缺失或
损坏抛 :class:`TrustFileError`(映射 500)。
"""

from __future__ import annotations

import base64
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import ValidationError

from .gs1 import ScanParseError, parse_scan
from .matcher import match_rules
from .models import CheckResponse, Rule, ScanErrorBody, ScanFields, ScanResult

DEFAULT_TRUST_FILE = "trust.json"
TRUST_FILE_ENV = "GS1_TRUST_FILE"

# RFC 7515: 三段均为 base64url 字符集(无填充);其余字符(含空白)一律非法
_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")


class SignedFormatError(Exception):
    """JWS / 载荷 / 规则格式非法(对应 HTTP 422)。"""


class SignedForbiddenError(Exception):
    """未知密钥、签名失败、越期或越权(对应 HTTP 403)。"""


class TrustFileError(Exception):
    """本地信任文件缺失或损坏(对应 HTTP 500)。"""


@dataclass(frozen=True)
class ParsedJws:
    """解析后的 compact JWS。"""

    kid: str
    nbf: int
    exp: int
    raw_rules: list  # 已通过 JSON 解析、尚未做规则校验的 rules
    signing_input: bytes  # 原始前两段以点连接的字节
    signature: bytes


# ---------- base64url 与 JSON(拒绝重复键) ----------


def b64url_decode(segment: str, what: str) -> bytes:
    """解码无填充 base64url 段;字符集、长度或填充非法时抛 SignedFormatError。"""
    if not segment or not _BASE64URL_RE.fullmatch(segment):
        raise SignedFormatError(f"{what} 不是合法的无填充 base64url")
    pad = "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(segment + pad)
    except Exception as exc:  # 理论上字符集校验后不会进入,防御性处理
        raise SignedFormatError(f"{what} base64url 解码失败") from exc


def _reject_duplicate_hook(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """object_pairs_hook:同层重复键直接拒绝(作用于任意嵌套层)。"""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise SignedFormatError(f"JSON 存在重复键: {key!r}")
        result[key] = value
    return result


def _loads_json(data: bytes, what: str) -> object:
    try:
        return json.loads(data, object_pairs_hook=_reject_duplicate_hook)
    except SignedFormatError:
        raise
    except json.JSONDecodeError as exc:
        raise SignedFormatError(f"{what} 不是合法 JSON: {exc.msg}") from exc


# ---------- JWS 解析与校验 ----------


def parse_jws(jws: str) -> ParsedJws:
    """解析并按格式要求校验 compact JWS(不验签)。"""
    if not isinstance(jws, str):
        raise SignedFormatError("jws 须为字符串")
    parts = jws.split(".")
    if len(parts) != 3 or any(part == "" for part in parts):
        raise SignedFormatError("JWS 须为恰好两个点分隔的三段非空 compact 序列化")
    header_seg, payload_seg, signature_seg = parts
    signing_input = f"{header_seg}.{payload_seg}".encode("ascii")

    header = _loads_json(b64url_decode(header_seg, "JWS 头部"), "JWS 头部")
    if not isinstance(header, dict) or set(header) != {"alg", "kid"}:
        raise SignedFormatError("JWS 头部须仅含 alg 与 kid 两个字段")
    if header["alg"] != "EdDSA":
        raise SignedFormatError("JWS 头部 alg 须为 'EdDSA'")
    kid = header["kid"]
    if not isinstance(kid, str) or not kid:
        raise SignedFormatError("JWS 头部 kid 须为非空字符串")

    payload = _loads_json(b64url_decode(payload_seg, "JWS 载荷"), "JWS 载荷")
    if not isinstance(payload, dict) or set(payload) != {"nbf", "exp", "rules"}:
        raise SignedFormatError("JWS 载荷须仅含 nbf、exp、rules 三个字段")
    nbf, exp = payload["nbf"], payload["exp"]
    # 显式排除 bool(bool 是 int 的子类)与 float
    if not isinstance(nbf, int) or isinstance(nbf, bool):
        raise SignedFormatError("JWS 载荷 nbf 须为整数")
    if not isinstance(exp, int) or isinstance(exp, bool):
        raise SignedFormatError("JWS 载荷 exp 须为整数")
    raw_rules = payload["rules"]
    if not isinstance(raw_rules, list) or not raw_rules:
        raise SignedFormatError("JWS 载荷 rules 须为非空数组")

    signature = b64url_decode(signature_seg, "JWS 签名")
    return ParsedJws(
        kid=kid,
        nbf=nbf,
        exp=exp,
        raw_rules=raw_rules,
        signing_input=signing_input,
        signature=signature,
    )


# ---------- 本地信任文件 ----------


@dataclass(frozen=True)
class TrustedKey:
    kid: str
    public_key: Ed25519PublicKey
    gtin_prefixes: tuple[str, ...]  # 1~14 位数字


@dataclass(frozen=True)
class TrustStore:
    keys: dict[str, TrustedKey]


@dataclass(frozen=True)
class _CachedStore:
    mtime: float
    size: int
    store: TrustStore


_STORE_CACHE: dict[str, _CachedStore] = {}


def trust_file_path() -> Path:
    """信任文件路径:环境变量 GS1_TRUST_FILE,缺省为工作目录下 trust.json。"""
    return Path(os.environ.get(TRUST_FILE_ENV, DEFAULT_TRUST_FILE))


def reset_trust_cache() -> None:
    """清空信任文件缓存(主要供测试使用)。"""
    _STORE_CACHE.clear()


def _build_trust_store(data: object) -> TrustStore:
    if not isinstance(data, dict) or set(data) != {"keys"}:
        raise TrustFileError("信任文件顶层须为仅含 keys 字段的对象")
    entries = data["keys"]
    if not isinstance(entries, list):
        raise TrustFileError("信任文件 keys 须为数组")
    keys: dict[str, TrustedKey] = {}
    for index, entry in enumerate(entries):
        where = f"信任文件 keys[{index}]"
        if not isinstance(entry, dict) or set(entry) != {"kid", "public_key", "gtin_prefixes"}:
            raise TrustFileError(f"{where} 须仅含 kid、public_key、gtin_prefixes 三个字段")
        kid = entry["kid"]
        if not isinstance(kid, str) or not kid:
            raise TrustFileError(f"{where} 的 kid 须为非空字符串")
        if kid in keys:
            raise TrustFileError(f"信任文件中 kid 重复: {kid!r}")
        raw_pub = entry["public_key"]
        if not isinstance(raw_pub, str):
            raise TrustFileError(f"{where} 的 public_key 须为无填充 base64url 字符串")
        try:
            pub_bytes = b64url_decode(raw_pub, f"{where} 的 public_key")
        except SignedFormatError as exc:
            raise TrustFileError(str(exc)) from exc
        try:
            public_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        except Exception as exc:
            raise TrustFileError(f"{where} 的公钥不是合法 Ed25519 公钥 (须为 32 字节原始公钥)") from exc
        prefixes_raw = entry["gtin_prefixes"]
        if not isinstance(prefixes_raw, list) or not prefixes_raw:
            raise TrustFileError(f"{where} 的 gtin_prefixes 须为非空数组")
        prefixes: list[str] = []
        for prefix in prefixes_raw:
            if (
                not isinstance(prefix, str)
                or not 1 <= len(prefix) <= 14
                or any(not "0" <= c <= "9" for c in prefix)
            ):
                raise TrustFileError(f"{where} 的 GTIN 前缀须为 1~14 位数字")
            if prefix in prefixes:
                raise TrustFileError(f"{where} 的 GTIN 前缀重复: {prefix!r}")
            prefixes.append(prefix)
        keys[kid] = TrustedKey(kid=kid, public_key=public_key, gtin_prefixes=tuple(prefixes))
    return TrustStore(keys=keys)


def load_trust_store() -> TrustStore:
    """读取本地信任文件;按 (路径, mtime, size) 缓存,不联网。"""
    path = trust_file_path()
    try:
        stat = path.stat()
    except OSError as exc:
        raise TrustFileError(f"信任文件不可读: {path}") from exc
    cache_key = str(path)
    cached = _STORE_CACHE.get(cache_key)
    if cached is not None and cached.mtime == stat.st_mtime and cached.size == stat.st_size:
        return cached.store
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise TrustFileError(f"信任文件不可读: {path}") from exc
    data = _loads_json(raw, "信任文件")  # 重复键同样拒绝
    store = _build_trust_store(data)
    _STORE_CACHE[cache_key] = _CachedStore(mtime=stat.st_mtime, size=stat.st_size, store=store)
    return store


# ---------- 规则校验与授权 ----------


def _validate_rules(raw_rules: list) -> list[Rule]:
    """把载荷中的 rules 按现有规则格式校验(id 唯一等),非法抛 SignedFormatError。"""
    if len(raw_rules) > 100:
        raise SignedFormatError("rules 数量须为 1~100 条")
    rules: list[Rule] = []
    for index, raw in enumerate(raw_rules):
        try:
            rules.append(Rule.model_validate(raw))
        except ValidationError as exc:
            first = exc.errors()[0]
            loc = ".".join(str(p) for p in first.get("loc", ()))
            raise SignedFormatError(
                f"rules[{index}] 非法: {loc + ' ' if loc else ''}{first['msg']}"
            ) from exc
    ids = [rule.id for rule in rules]
    if len(set(ids)) != len(ids):
        raise SignedFormatError("规则 ID 必须唯一")
    return rules


def _authorize_gtin_prefixes(rules: list[Rule], trusted: TrustedKey) -> None:
    """每条规则的 GTIN 至少匹配一个授权前缀,否则越权 403。"""
    for rule in rules:
        if not any(rule.gtin.startswith(prefix) for prefix in trusted.gtin_prefixes):
            raise SignedForbiddenError(
                f"规则 {rule.id!r} 的 GTIN {rule.gtin} 不在 kid {trusted.kid!r} "
                f"授权的 GTIN 前缀范围内"
            )


# ---------- 总入口 ----------


def verify_signed_check(scans: list[str], jws: str, now: int) -> tuple[str, CheckResponse]:
    """验签 + 时间窗 + 授权前缀 + 规则校验全部通过后,返回 (kid, 原扫码核验结果)。"""
    parsed = parse_jws(jws)

    store = load_trust_store()
    trusted = store.keys.get(parsed.kid)
    if trusted is None:
        raise SignedForbiddenError(f"未知密钥 kid: {parsed.kid!r}")

    try:
        trusted.public_key.verify(parsed.signature, parsed.signing_input)
    except InvalidSignature as exc:
        raise SignedForbiddenError("Ed25519 签名验证失败") from exc

    # 签名真实后:先按现有格式校验规则(非法一律 422),再查时间窗与授权(403)
    rules = _validate_rules(parsed.raw_rules)

    if not parsed.nbf <= now < parsed.exp:
        raise SignedForbiddenError(
            f"载荷不在有效期内: nbf={parsed.nbf}, exp={parsed.exp}, now={now}"
        )

    _authorize_gtin_prefixes(rules, trusted)

    results: list[ScanResult] = []
    for index, raw in enumerate(scans):
        try:
            parsed_scan = parse_scan(raw)
        except ScanParseError as exc:
            results.append(
                ScanResult(
                    index=index,
                    ok=False,
                    error=ScanErrorBody(offset=exc.offset, reason=exc.reason),
                )
            )
            continue
        results.append(
            ScanResult(
                index=index,
                ok=True,
                fields=ScanFields(
                    gtin=parsed_scan.gtin,
                    batch=parsed_scan.batch,
                    serial=parsed_scan.serial,
                    date=parsed_scan.expiry,
                ),
                matches=match_rules(parsed_scan, rules),
            )
        )
    return parsed.kid, CheckResponse(results=results)
