# GS1 扫码核验 API

基于 FastAPI 的 GS1 条码解析服务,提供五个接口:

- **召回核验**:上传一批扫描串和一批召回规则,逐条返回解析出的字段(GTIN / 批号 / 序列号 / 日期)以及命中的规则 ID。
- **召回规则关系分析**:上传 2~100 条召回规则,上线前找出不可能命中任何合法扫描串的规则,以及命中集合有交集的规则对(等价 / 包含 / 部分相交),每对附一条同时命中两者的证据扫描串。
- **交接审计**:上传一批实物交接事件,按时间重放并审计每件实物(GTIN + 序列号)的持有人流转,返回成功事件与失败原因。
- **装拆包装审计**:上传一批按顺序执行的装入 / 取出操作,重放并审计实物(GTIN + 序列号)间的直接包装关系,返回涉及实物的直接父件 / 子件 / 最外层容器与失败原因。
- **召回隔离计划**:上传库存扫描、召回规则、装拆操作与已封签实物扫描串,命中召回的实物沿最终包装父链归并到最高层已封签祖先,输出隔离单元。

## 快速启动

```bash
docker compose up --build
```

服务监听 **8000** 端口:

- 召回核验:`POST http://localhost:8000/v1/recall/check`
- 召回规则关系分析:`POST http://localhost:8000/v1/recall/rule-relations`
- 交接审计:`POST http://localhost:8000/v1/custody/audit`
- 装拆包装审计:`POST http://localhost:8000/v1/packing/audit`
- 召回隔离计划:`POST http://localhost:8000/v1/recall/isolation-plan`
- 交互文档:`http://localhost:8000/docs`
- 健康检查:`GET http://localhost:8000/healthz`

本地开发(无需 Docker):

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

运行测试:

```bash
pip install pytest httpx
pytest
```

## 接口说明

### `POST /v1/recall/check`

请求体:

| 字段 | 类型 | 约束 |
| --- | --- | --- |
| `scans` | `string[]` | 1~100 条扫描串 |
| `rules` | `object[]` | 1~100 条规则,`id` 必须唯一 |

规则字段:

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `id` | 是 | 规则 ID,1~64 字符,请求内唯一 |
| `gtin` | 是 | 14 位数字,须通过 GS1 模 10 校验位 |
| `batch` | 否 | 批号,1~20 位可打印 ASCII;附带时扫描串须含 AI 10 且相等 |
| `serial` | 否 | 序列号,1~20 位可打印 ASCII;附带时扫描串须含 AI 21 且相等 |
| `date_from` / `date_to` | 否 | ISO 日期(`YYYY-MM-DD`)闭区间;附带时扫描串须含 AI 17 且日期落在区间内(含端点) |

规则不合法(GTIN 校验位错误、ID 重复、数量超限、日期区间倒置等)时整个请求返回 **422**。

### 扫描串语法

- 可带符号标识符前缀 `]d2`(GS1 DataMatrix)。
- FNC1 为 **ASCII 29**(`\x1d`,GS),用作字段分隔符。
- 支持的 AI,可按**任意顺序**出现,每种**至多一次**:

| AI | 含义 | 格式 |
| --- | --- | --- |
| `01` | GTIN | 定长 14 位数字,模 10 校验位,**必填** |
| `17` | 日期 | 定长 6 位 `YYMMDD`,年按 2000~2099 解释,日 `00` 取当月末日 |
| `10` | 批号 | 变长 1~20 位可打印 ASCII,**仅由 FNC1 或串尾结束** |
| `21` | 序列号 | 变长 1~20 位可打印 ASCII,**仅由 FNC1 或串尾结束** |

定长字段后的 FNC1 可省略;变长字段若后面还有 AI,必须用 FNC1 分隔,否则后续内容会被吞进该字段。

### 响应

```json
{
  "results": [
    {
      "index": 0,
      "ok": true,
      "fields": {
        "gtin": "09506001123454",
        "batch": "LOT1",
        "serial": "SN9",
        "date": "2025-12-31"
      },
      "matches": ["recall-2026-001"],
      "error": null
    },
    {
      "index": 1,
      "ok": false,
      "fields": null,
      "matches": [],
      "error": { "offset": 16, "reason": "未知 AI: '99'" }
    }
  ]
}
```

- `results` 与 `scans` 一一对应,`index` 为扫描串下标。
- `ok=true`:`fields` 为解析出的字段(`date` 为 AI 17 解析结果,ISO 格式),`matches` 为命中的规则 ID,**按请求中规则的顺序排列**。
- `ok=false`:解析失败,`error.offset` 为出错位置(**相对原始扫描串、含 `]d2` 前缀,从 0 计**),`error.reason` 为原因(未知 AI、非法字符、长度不足 / 超长、分隔符误用、校验位错误、日期非法、缺少 AI 01 等)。**单条失败不影响其余条目**。

### 示例

```bash
curl -s http://localhost:8000/v1/recall/check \
  -H 'Content-Type: application/json' \
  -d '{
    "scans": ["]d201095060011234541725123110LOT1\u001d21SN9"],
    "rules": [
      {"id": "recall-2026-001", "gtin": "09506001123454", "batch": "LOT1",
       "date_from": "2025-01-01", "date_to": "2026-12-31"}
    ]
  }'
```

> JSON 中 FNC1 写作 `\u001d`;shell 里也可用 `$'...\x1d...'` 构造。

### `POST /v1/recall/rule-relations`

召回规则上线前的静态检查:不必提供扫描串,直接比较规则两两的命中集合,找出可能命中同一扫描串的规则对。

请求体:

| 字段 | 类型 | 约束 |
| --- | --- | --- |
| `rules` | `object[]` | **2~100** 条规则,格式同召回核验,`id` 必须唯一 |

处理规则:

1. **不可能命中的规则**:AI 17 只能表达 2000~2099 年的合法日期,规则的日期区间夹取到该范围后为空(如 `date_to` 早于 2000-01-01、或 `date_from` 晚于 2099-12-31)时,该规则不可能命中任何合法扫描串,其 ID 按**输入顺序**列入 `impossible_rule_ids`,不参与两两比较。
2. **规则对比较**:其余规则两两比较命中集合(匹配语义同召回核验:GTIN 相等为前提;批号 / 序列号附带时须相等;日期区间须相交),仅返回**有交集**的规则对,按 `(left_index, right_index)` 输入下标排序。
3. 每对附一条**同时命中两者**的合法 GS1 扫描串 `witness`:批号、序列号只在约束需要时出现;日期有约束时取**交集内最早一天**;变长字段(AI 10/21)后仍有 AI 时加 FNC1。

响应:

```json
{
  "impossible_rule_ids": ["recall-legacy"],
  "pairs": [
    {
      "left_index": 0,
      "right_index": 1,
      "left_id": "recall-all",
      "right_id": "recall-lot1",
      "relation": "left_contains_right",
      "witness": "010950600112345410LOT1"
    }
  ]
}
```

`relation` 取值:

| 值 | 含义 |
| --- | --- |
| `equivalent` | 等价:两条规则的命中集合相同 |
| `left_contains_right` | 左包含右:右规则(下标较大者)的命中集合是左规则的真子集 |
| `right_contains_left` | 右包含左:左规则的命中集合是右规则的真子集 |
| `partial_overlap` | 部分相交:有交集但互不包含 |

规则不合法(数量不足 2 条或超限、GTIN 校验位错误、ID 重复、日期区间倒置等)时整个请求返回 **422**。

示例:

```bash
curl -s http://localhost:8000/v1/recall/rule-relations \
  -H 'Content-Type: application/json' \
  -d '{
    "rules": [
      {"id": "recall-all",      "gtin": "09506001123454"},
      {"id": "recall-lot1",     "gtin": "09506001123454", "batch": "LOT1"},
      {"id": "recall-lot1-exp", "gtin": "09506001123454", "batch": "LOT1",
       "date_from": "2025-01-01", "date_to": "2025-06-30"},
      {"id": "recall-legacy",   "gtin": "09506001123454", "date_to": "1999-12-31"}
    ]
  }'
```

响应中 `recall-legacy` 因日期区间完全在 2000 年之前而被列入 `impossible_rule_ids`;其余三条规则两两构成 `left_contains_right` 关系,`witness` 如 `01095060011234541725010110LOT1`(含 AI 17 2025-01-01 与批号 LOT1,同时命中 `recall-all` 与 `recall-lot1-exp`)。

### `POST /v1/custody/audit`

审计一批实物交接事件:按发生时间重放,维护每件实物(**GTIN + AI 21 序列号**)的持有人,返回每件实物的成功递交结果与失败事件的原因。

请求体:

| 字段 | 类型 | 约束 |
| --- | --- | --- |
| `events` | `object[]` | 1~300 条交接事件 |

事件字段:

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `scan` | 是 | GS1 扫描串,语法同召回核验;须含 AI 01 与 AI 21(序列号) |
| `occurred_at` | 是 | ISO 8601 时间,**须带时区**(如 `2026-09-01T08:30:00+08:00`) |
| `from_location` | 是(可为 `null`) | 交出方;实物的首次事件须为 `null` |
| `to_location` | 是 | 接收方,**非空**字符串 |

处理规则:

1. 事件按 `occurred_at` **转 UTC 后升序**处理;同一时刻依输入顺序。
2. 扫描非法或缺少 AI 21 序列号的事件按原下标报错,不参与流转。
3. 每件实物的**首次成功事件** `from_location` 须为 `null`;后续事件 `from_location` 须等于**上次成功事件**的 `to_location`。
4. 批号(AI 10)、有效期(AI 17)须与首次成功扫描一致(**含字段缺失**:首次没有该字段时,后续也不能有),否则记录冲突且**不改变持有人**。
5. 只有成功事件参与流转;失败事件不影响后续事件的判定基准。

响应:

```json
{
  "items": [
    {
      "gtin": "09506001123454",
      "serial": "SN9",
      "events": [1, 0],
      "holder": "WH-B"
    }
  ],
  "errors": [
    { "index": 2, "reason": "from_location 须等于上次成功事件的 to_location 'WH-B',实际为 'WH-X'" }
  ]
}
```

- `items` 按 **GTIN、序列号**排序;`events` 为该实物成功事件的原始下标(按处理顺序,即时间升序),`holder` 为最终持有人(最后一次成功事件的 `to_location`)。
- `errors` 按**原始下标**排序,`reason` 说明失败原因(扫描非法、缺少序列号、首次事件 `from_location` 非 `null`、交接链断裂、批号 / 有效期冲突)。
- 请求体不合法(事件数量超限、`occurred_at` 缺时区、`to_location` 为空、字段缺失或多余等)时整个请求返回 **422**。

示例:

```bash
curl -s http://localhost:8000/v1/custody/audit \
  -H 'Content-Type: application/json' \
  -d '{
    "events": [
      {"scan": "01095060011234541725123110LOT1\u001d21SN9",
       "occurred_at": "2026-09-01T09:00:00+08:00",
       "from_location": null, "to_location": "WH-A"},
      {"scan": "01095060011234541725123110LOT1\u001d21SN9",
       "occurred_at": "2026-09-01T10:00:00+08:00",
       "from_location": "WH-A", "to_location": "WH-B"}
    ]
  }'
```

### `POST /v1/packing/audit`

审计一批**按输入顺序执行**的装入 / 取出操作:父件与子件均以 GS1 扫描串给出(语法同召回核验),以 **GTIN + AI 21 序列号**唯一识别实物;重放后返回成功操作涉及的全部实物及其当前包装关系,以及失败操作的原因。

请求体:

| 字段 | 类型 | 约束 |
| --- | --- | --- |
| `operations` | `object[]` | 1~300 条装/拆操作,**严格按下标顺序执行** |

操作字段:

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `action` | 是 | `"pack"`(装入)或 `"unpack"`(取出) |
| `parent_scan` | 是 | 父件 GS1 扫描串,须含 AI 01 与 AI 21(序列号) |
| `child_scan` | 是 | 子件 GS1 扫描串,须含 AI 01 与 AI 21(序列号) |

处理规则:

1. 两端扫描串复用同一套 GS1 解析;任一端非法、或缺少 AI 21 序列号,该操作按**原下标**报错且不改变任何关系。
2. **装入(pack)**:子件须**尚无父件**;且不能是父件本身,也不能是父件的祖先(防止自装 / 形成循环包装)。父件若此前未出现,记为无父件的新实物。
3. **取出(unpack)**:父件、子件均须为已知实物,且指定的父件必须是子件的**当前直接父件**(祖父件不可直接取出孙子件)。
4. **失败操作不改变包装关系**,后续操作照常处理;只有成功操作涉及的实物才会出现在响应中。

响应:

```json
{
  "items": [
    {
      "gtin": "09506001123454",
      "serial": "PALLET-A",
      "parent": null,
      "children": [{ "gtin": "09506001123461", "serial": "CASE-1" }],
      "root": { "gtin": "09506001123454", "serial": "PALLET-A" }
    },
    {
      "gtin": "09506001123461",
      "serial": "CASE-1",
      "parent": { "gtin": "09506001123454", "serial": "PALLET-A" },
      "children": [],
      "root": { "gtin": "09506001123454", "serial": "PALLET-A" }
    }
  ],
  "errors": [
    { "index": 1, "reason": "取出失败:指定的父件实物 (GTIN 09506001123478, 序列号 'PALLET-X')此前未出现在任何成功操作中" }
  ]
}
```

- `items` 为**成功操作涉及的全部实物**,按 **GTIN、序列号**排序。
  - `parent`:当前直接父件引用;无父件时为 `null`。
  - `children`:当前直接子件引用列表,按 **GTIN、序列号**同样排序。
  - `root`:沿父链向上找到的**最外层容器**引用;无父件时即为实物**自身**。
  - 引用对象形如 `{"gtin": "...", "serial": "..."}`。
- `errors` 按**原始下标**排序,`reason` 说明失败原因(父件 / 子件扫描非法、缺少序列号、子件已有父件、子件即父件本身、装入祖先成环、取出未指定当前直接父件等)。
- 请求体不合法(操作数量超限、`action` 取值非法、字段缺失或多余等)时整个请求返回 **422**。

示例:

```bash
curl -s http://localhost:8000/v1/packing/audit \
  -H 'Content-Type: application/json' \
  -d '{
    "operations": [
      {"action": "pack",
       "parent_scan": "010950600112345421PALLET-A",
       "child_scan":  "010950600112346121CASE-1"},
      {"action": "unpack",
       "parent_scan": "010950600112347821PALLET-X",
       "child_scan":  "010950600112346121CASE-1"}
    ]
  }'
```

上例第 0 条装入成功;第 1 条取出因指定的父件不是当前直接父件而失败(且不改变关系)。

### `POST /v1/recall/isolation-plan`

生成召回隔离计划:库存扫描命中召回规则后,把命中实物沿**最终包装父链**归并到**最高层已封签祖先**(含实物自身),输出待隔离的单元。

请求体:

| 字段 | 类型 | 约束 |
| --- | --- | --- |
| `scans` | `string[]` | 1~100 条库存扫描串,须含 AI 21(序列号) |
| `rules` | `object[]` | 1~100 条召回规则,格式同召回核验,`id` 必须唯一 |
| `operations` | `object[]` | 1~300 条装/拆操作,格式同装拆包装审计,**严格按下标顺序执行** |
| `sealed_scans` | `string[]` | 0~300 条已封签实物扫描串,须含 AI 21(序列号) |

处理规则:

1. **封签扫描**(`sealed_scans`)须全部合法、含 AI 21 且 GTIN+序列号不重复,否则整个请求返回 **422**。
2. **库存扫描**(`scans`)逐条解析,须含 AI 21;非法或缺序列号的扫描按**原下标**记入 `errors` 并跳过,不影响其余条目。**合法**扫描的 GTIN+序列号重复时,整个请求返回 **422**。
3. **装拆操作**(`operations`)复用装拆包装审计的重放逻辑:失败操作**不改变包装关系**,按**原下标**记入 `operation_errors`。
4. 合法库存扫描复用召回核验的规则匹配;**未命中任何规则的扫描不产出单元**。
5. 对每件命中召回的实物,沿重放后的**最终父链**向上选**最高层已封签祖先**(含实物自身)作为隔离单元;父链上没有已封签祖先时,单元即为该实物自身。
6. 归入同一单元的命中扫描合并:`scan_indices` 为命中库存扫描的原始下标(升序),`rule_ids` 为命中的规则 ID(**去重后保持规则输入顺序**)。

响应:

```json
{
  "units": [
    {
      "gtin": "09506001123454",
      "serial": "PALLET-A",
      "scan_indices": [0, 2],
      "rule_ids": ["recall-2026-001"]
    }
  ],
  "errors": [
    { "index": 1, "reason": "扫描串缺少 AI 21 序列号,无法识别实物" }
  ],
  "operation_errors": [
    { "index": 2, "reason": "装入失败:子件实物 (GTIN 09506001123461, 序列号 'CASE-1')已有直接父件实物 (GTIN 09506001123454, 序列号 'PALLET-A'),不能重复装入" }
  ]
}
```

- `units` 按 **GTIN、序列号**排序;`errors`(库存扫描)与 `operation_errors`(装拆操作)均按**原始下标**排序。
- 请求体不合法(数量超限、规则 ID 重复、字段缺失或多余等),或封签扫描非法 / 缺序列号 / 重复,或合法库存扫描重复时,整个请求返回 **422**。

示例:库存中 `CASE-1`(下标 0)与 `CASE-2`(下标 2)都装在已封签的托盘 `PALLET-A` 里,且都命中召回规则;下标 1 的库存扫描缺序列号被跳过;下标 2 的装入操作因重复装入而失败。

```bash
curl -s http://localhost:8000/v1/recall/isolation-plan \
  -H 'Content-Type: application/json' \
  -d '{
    "scans": [
      "010950600112346121CASE-1",
      "010950600112345417251231",
      "010950600112347821CASE-2"
    ],
    "rules": [
      {"id": "recall-2026-001", "gtin": "09506001123461"},
      {"id": "recall-2026-002", "gtin": "09506001123478"}
    ],
    "operations": [
      {"action": "pack",
       "parent_scan": "010950600112345421PALLET-A",
       "child_scan":  "010950600112346121CASE-1"},
      {"action": "pack",
       "parent_scan": "010950600112345421PALLET-A",
       "child_scan":  "010950600112347821CASE-2"},
      {"action": "pack",
       "parent_scan": "010950600112345421PALLET-A",
       "child_scan":  "010950600112346121CASE-1"}
    ],
    "sealed_scans": ["010950600112345421PALLET-A"]
  }'
```

响应中两个命中实物被归并到同一个隔离单元 `PALLET-A`:`units[0].scan_indices` 为 `[0, 2]`,`rule_ids` 为 `["recall-2026-001", "recall-2026-002"]`。

## 项目结构

```
app/
  main.py      # FastAPI 入口与路由
  gs1.py       # GS1 扫描串解析(AI 01/10/17/21、FNC1、]d2、校验位、日期)
  models.py    # 请求 / 响应模型与规则校验
  matcher.py   # 召回规则匹配
  relations.py # 召回规则关系分析(命中集合比较与证据扫描串构造)
  custody.py   # 实物交接审计(按时间重放事件,维护持有人)
  packing.py   # 装拆包装审计(按输入顺序重放装/拆操作,维护父子关系)
  isolation.py # 召回隔离计划(命中实物沿最终父链归并到最高层已封签祖先)
tests/
  test_recall.py
  test_relations.py
  test_custody.py
  test_packing.py
  test_isolation.py
Dockerfile
docker-compose.yml
requirements.txt
```
