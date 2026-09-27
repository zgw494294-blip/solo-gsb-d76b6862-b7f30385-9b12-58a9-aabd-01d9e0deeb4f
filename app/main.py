"""GS1 扫码核验 API:召回规则匹配 + 实物交接审计。"""

from __future__ import annotations

from fastapi import FastAPI

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
)
from .packing import audit_packing
from .relations import analyze_rule_relations

app = FastAPI(
    title="GS1 扫码核验 API",
    version="1.4.0",
    summary="解析 GS1 扫描串(AI 01/10/17/21):召回规则匹配、规则关系分析、实物交接重放、装拆包装审计与召回隔离计划",
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
