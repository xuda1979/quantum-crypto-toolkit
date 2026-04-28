# 抗量子算法工具集

这个仓库实现 `/Users/daxu/PATENTS` 中两个抗量子通信方案的可运行工具集原型：

- `1_QCH-KEM_Quantum-Classical_Hybrid`：量子-经典混合密钥封装机制。
- `4_DLHP_Dynamic_Lattice-Hopping`：动态多原语密码跳频协议。

代码只依赖 Python 标准库，适合协议验证、流程演示、集成接口打样和测试。当前底层 ML-KEM、QKD 和每跳加密器是演示适配器，不是经过审计的生产密码实现。

当前版本按测试驱动开发：新增能力先写测试，再补实现。`python3 -m pytest` 覆盖策略推荐、QCH 审计、DLHP 阈值保护、受保护单元、重放拒绝、诱饵包和 CLI JSON 输出。

## 功能

- QCH-KEM
  - QKD 状态监测和 `NORMAL` / `DEGRADED` / `FALLBACK` / `RECOVERY` 状态机。
  - 根据 QKD 可用密钥材料选择 `ML-KEM-512` / `768` / `1024` 参数档。
  - 用 HKDF 组合 PQC 共享秘密和 QKD 密钥材料。
  - 完整握手确认 MAC 流程。
  - QRNG/QKD 健康元数据、带宽估计、安全裕量和审计事件输出。

- DLHP
  - 基于 `SeqID` 的无状态算法跳迁调度。
  - 相邻硬问题类别正交约束。
  - Shamir `(k,n)` 阈值分片和重构。
  - 每个分片独立派生密钥、认证、保护，并绑定算法和路径元数据。
  - 受保护单元 header/ciphertext/tag 封装，header 默认不暴露算法名。
  - 接收端 replay window，拒绝重复或过旧序列号。
  - 算法 chaff/decoy 生成，外形与正常包一致，合法接收端可丢弃。

- 策略与算法目录
  - 面向 `balanced`、`high_assurance`、`bandwidth_constrained`、`long_term_archive`、`experimental_diversity` 的推荐套件。
  - 区分标准化、候选、实验性和“已选待标准化”算法状态。
  - 2026-04 现状：NIST FIPS 203/204/205 已发布；HQC 于 2025 年被 NIST 选为补充 KEM，最终标准仍待完成。

## 快速运行

```bash
python3 -m qcrypto_toolkit.cli qch-demo --qkd-bytes 64 --qkd-rate 10000 --qber 0.01
python3 -m qcrypto_toolkit.cli qch-demo --qkd-bytes 0
python3 -m qcrypto_toolkit.cli recommend --profile long_term_archive
python3 -m qcrypto_toolkit.cli catalog --kind kem --min-security-bits 192
python3 -m qcrypto_toolkit.cli report --profile long_term_archive --schedule-count 20
python3 -m qcrypto_toolkit.cli matrix balanced long_term_archive high_assurance --schedule-count 20
python3 -m qcrypto_toolkit.cli campaign --scenario healthy:64:10000:0.01:20 --scenario fallback:0:0:0:20 --profiles balanced,long_term_archive,bandwidth_constrained
python3 -m qcrypto_toolkit.cli campaign --scenario-file /absolute/path/campaign.json --profiles balanced,long_term_archive,high_assurance
python3 -m qcrypto_toolkit.cli sweep balanced long_term_archive high_assurance --qkd-bytes-values 0,8,32,64 --qkd-rate-values 0,2000,10000 --qber-values 0,0.02,0.08
python3 -m qcrypto_toolkit.cli dlhp-schedule --count 20
python3 -m qcrypto_toolkit.cli dlhp-protect "hello post quantum" --k 3 --n 5
python3 -m qcrypto_toolkit.cli dlhp-unit "hello packet" --seq-id 9
python3 -m qcrypto_toolkit.cli dlhp-chaff --count 3 --payload-size 32
```

启动本地 GUI：

```bash
python3 -m qcrypto_toolkit.cli gui --host 127.0.0.1 --port 8765
```

然后打开 `http://127.0.0.1:8765`。GUI 是标准库实现的本地控制台，不需要 Node、npm 或额外前端依赖，包含 QCH-KEM 握手、策略推荐、算法目录、DLHP 调度预览、DLHP 受保护单元、诱饵包生成、综合安全报告、多部署画像对比矩阵、独立的多场景 Campaign Planner，以及新的 Condition Sweep 边界扫描台。

GUI 采用控制台式布局：左侧工具导航、顶部运行状态、四个核心指标卡、工具参数面板、调度时间线、JSON 摘要、复制和下载按钮。Overview 首页现在默认展示多画像矩阵，可快速比较 `balanced`、`high_assurance`、`bandwidth_constrained`、`long_term_archive` 在相同 QKD 条件下的 QCH 配置和 DLHP 轮换差异，并给出“最高安全 / 最低带宽 / 最大多样性”三个自动摘要。矩阵还会输出综合评分、排序、推荐画像和每个画像的 trade-off 提示，GUI 中也会渲染为可读表格。

`matrix` 的评分权重现在可调。CLI 和 `/api/matrix` 支持 `security_weight`、`diversity_weight`、`rotation_weight`、`bandwidth_penalty`、`findings_penalty`、`state_penalty`、`orthogonality_penalty`，适合把“偏重安全”或“偏重带宽”的判断准则显式化。每一行还会返回 `score_breakdown`，说明总分由哪些维度组成。

GUI Overview 还支持前端排序和筛选：可以按总分、带宽、多样性或安全档位重排矩阵，并按 profile/trade-off 文本快速过滤结果。

当需要把软件做大到多现实条件分析时，可以使用 `campaign`。它会对一组场景分别运行矩阵分析，再聚合每个 profile 的 `scenario_wins`、`average_score`、`average_rank`、`fallback_count`、状态分布、最佳/最差场景以及 `why_it_wins` / `why_it_loses` 解释，适合比较“健康链路 / 受限链路 / fallback”一类组合。

`campaign` 现在支持两种输入方式：

- 命令行重复 `--scenario name:qkd_bytes:qkd_rate:qber:schedule_count`
- `--scenario-file` 指向 JSON 文件或换行分隔的文本文件

示例 JSON：

```json
{
  "scenarios": [
    { "name": "healthy", "qkd_bytes": 64, "qkd_rate": 10000, "qber": 0.01, "schedule_count": 20 },
    { "name": "stressed", "qkd_bytes": 8, "qkd_rate": 2000, "qber": 0.08, "schedule_count": 20 },
    { "name": "fallback", "qkd_bytes": 0, "qkd_rate": 0, "qber": 0.0, "schedule_count": 20 }
  ]
}
```

GUI 的 Campaign Planner 会直接渲染聚合排名表、场景表和当前选中场景的 profile matrix，适合把原本一次性的 API 输出变成可交互的多场景决策台。

如果不想手工写很多 scenario，可以直接用 `sweep`。它会自动扫描一组 `qkd_bytes`、`qkd_rate`、`qber` 组合，批量运行 matrix，然后汇总：

- 每个 profile 作为 leader 的覆盖点数和覆盖率
- 平均分、平均 rank、正常态比例和 fallback 比例
- leader 在不同 QBER 车道上的切换次数和切换点

这更适合找“画像分界线”，例如在哪个 `qber` 或 `qkd_rate` 区间应该从 `long_term_archive` 切到 `bandwidth_constrained`。

`sweep` 输入支持逗号列表或 `start:stop:step` 范围：

```bash
python3 -m qcrypto_toolkit.cli sweep balanced long_term_archive \
  --qkd-bytes-values 0:64:16 \
  --qkd-rate-values 0,2000,10000 \
  --qber-values 0:0.08:0.02
```

GUI 的 Sweep 面板会渲染 profile 覆盖表，并在下方继续展示某个扫描点的 matrix 视图，适合快速看总览后再落回具体条件。

CLI 和 GUI 共享输入校验：`qber` 必须在 `0..1`，计数/字节类参数必须非负。无效输入会返回清晰错误，而不是继续生成误导性的 demo 输出。

运行测试：

```bash
python3 -m pytest
```

可选浏览器回归测试：

```bash
npm install
npx playwright install chromium
npm run test:gui
```

该测试会打开本地 GUI，点击主要工具，检查 JSON 输出、控制台错误和移动端横向溢出。

如果没有安装 `pytest`，可以先运行内置 smoke test：

```bash
python3 -m qcrypto_toolkit.cli qch-demo
python3 -m qcrypto_toolkit.cli dlhp-protect "smoke"
```

## 生产化边界

生产版本需要替换这些演示组件：

- `DemoMLKEMAdapter` -> FIPS 203 / ML-KEM 实现。
- `QKDKeyBuffer` -> 真实 QKD 设备或密钥管理系统接口。
- DLHP 的 `_stream` XOR 保护器 -> AEAD，例如 AES-GCM、ChaCha20-Poly1305 或经批准的国密套件。
- 密钥擦除、侧信道防护、审计日志、重放窗口和传输层绑定。

默认 CLI 不打印 session key；需要调试时显式传 `--show-key`。不要把演示密钥或输出当作真实安全材料使用。
