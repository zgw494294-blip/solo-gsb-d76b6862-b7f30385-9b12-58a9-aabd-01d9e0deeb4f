"""GS1 扫码核验 API:召回规则匹配 + 实物交接审计。"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException

from .custody import audit_custody
from .gs1 import ScanParseError, parse_scan
from .isolation import build_isolation_plan
from .matcher import match_rules
from .models import (
    CheckRequest,
    CheckResponse,
    CustodyAuditRequest,
    CustodyAuditResponse,
    IsolationPlanRequest,
    IsolationPlanResponse,
    PackingAuditRequest,
    PackingAuditResponse,
    RuleRelationsRequest,
    RuleRelationsResponse,
    ScanErrorBody,
    ScanFields,
    ScanResult,
    SignedCheckRequest,
    SignedCheckResponse,
)
from .packing import audit_packing
from .relations import analyze_rule_relations
from .signed import (
    SignedForbiddenError,
    SignedFormatError,
    TrustFileError,
    verify_signed_check,
)

app = FastAPI(
    title="GS1 扫码核验 API",
    version="1.5.0",
    summary="解析 GS1 扫描串(AI 01/10/17/21):召回规则匹配、签名召回核验、规则关系分析、实物交接重放、装拆包装审计与召回隔离计划",
)


@app.get("/healthz", tags=["meta"])
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/recall/check", response_model=CheckResponse, tags=["recall"])
def recall_check(request: CheckRequest) -> CheckResponse:
    """逐条解析扫描串并匹配召回规则;单条解析失败不影响其余条目。"""
    results: list[ScanResult] = []
    for index, raw in enumerate(request.scans):
        try:
            parsed = parse_scan(raw)
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
                    gtin=parsed.gtin,
                    batch=parsed.batch,
                    serial=parsed.serial,
                    date=parsed.expiry,
                ),
                matches=match_rules(parsed, request.rules),
            )
        )
    return CheckResponse(results=results)


@app.post(
    "/v1/recall/check-signed", response_model=SignedCheckResponse, tags=["recall"]
)
def recall_check_signed(request: SignedCheckRequest) -> SignedCheckResponse:
    """校验 compact JWS(Ed25519):本地信任文件查公钥、时间窗与 GTIN 前缀授权全部
    通过后,执行与 /v1/recall/check 一致的扫码核验并返回 kid 与结果。

    JWS 或载荷规则格式非法返回 422;未知密钥、签名失败、越期或越权返回 403,
    均不返回匹配结果。
    """
    try:
        kid, check = verify_signed_check(request.scans, request.jws, request.now)
    except SignedFormatError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except SignedForbiddenError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except TrustFileError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return SignedCheckResponse(kid=kid, results=check.results)


@app.post("/v1/custody/audit", response_model=CustodyAuditResponse, tags=["custody"])
def custody_audit(request: CustodyAuditRequest) -> CustodyAuditResponse:
    """按时间(UTC 升序)重放交接事件,审计每件实物(GTIN+序列号)的持有人流转。"""
    return audit_custody(request)


@app.post("/v1/packing/audit", response_model=PackingAuditResponse, tags=["packing"])
def packing_audit(request: PackingAuditRequest) -> PackingAuditResponse:
    """按输入顺序重放装入/取出操作,审计实物(GTIN+序列号)间的直接包装关系。"""
    return audit_packing(request)


@app.post(
    "/v1/recall/isolation-plan", response_model=IsolationPlanResponse, tags=["recall"]
)
def recall_isolation_plan(request: IsolationPlanRequest) -> IsolationPlanResponse:
    """库存扫描命中召回规则后,沿最终包装父链归并到最高层已封签祖先,输出隔离单元。"""
    return build_isolation_plan(request)


@app.post(
    "/v1/recall/rule-relations", response_model=RuleRelationsResponse, tags=["recall"]
)
def recall_rule_relations(request: RuleRelationsRequest) -> RuleRelationsResponse:
    """上线前比较召回规则的命中集合:列出不可能命中的规则与有交集的规则对。"""
    return analyze_rule_relations(request)
