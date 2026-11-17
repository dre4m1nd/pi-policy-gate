**[简体中文](README.md) | [English](README.en.md)**

<div align="center">

# pi-policy-gate

**面向 [Pi](https://github.com/earendil-works/pi) 编码代理的、可版本化、可审计的权限策略引擎。**

代理发出的每一次工具调用（bash、文件读写、MCP、技能、特殊操作）都会经过一道确定性闸门。
本工程把这道闸门从一个只在运行时生效的开关，变成可以**版本化、审计、离线回归测试**的东西。

</div>

## 为什么需要它

编码代理以用户的完整权限运行。一次提示注入、一个被带偏的模型，或者一条粗心的规则，
都可能删掉仓库、推错分支，或者外泄凭证。解决办法是在每次工具调用前设置一道确定性的权限闸门
——但一道你无法观测的闸门，就是一道你无法信任的闸门。pi-policy-gate 补充了让权限策略
可被验证的三件事：

- **版本化** —— 每个决策都绑定到有效策略的内容哈希，因此你总能回答“这个决策是哪条策略产生的？”。
- **审计** —— 每个决策都以只追加、已脱敏的 JSONL 记录落盘，可从 TUI 查看，也可导出给 CI。
- **仿真** —— 用一份固定的工具调用语料对策略求值，产出决策矩阵、规则覆盖率、死规则检测，
  以及两个策略版本之间的决策差异。

pi-policy-gate 在确定性权限求值内核（通配匹配、last-match-wins、分层配置）之上构建了可治理的
策略层：策略版本化、审计账本与离线仿真器，让权限策略可被验证、回归与审计。

## 工作原理

闸门是一条三阶段的纯管线。线上处理器与离线仿真器共用完全相同的求值路径，
因此一次通过的仿真就意味着线上闸门会与预期决策一致。

```
tool call (tool, command/args)
        │
        ▼
┌─────────────────────┐
│  1. resolve         │  该代理的有效策略 + 其版本（内容哈希）
│  2. evaluate        │  与已编译规则匹配（last-match-wins）
│  3. decide          │  allow / deny / ask
└─────────────────────┘
        │
        ├─ allow ───────────────► 执行
        ├─ deny  ───────────────► 拦截
        └─ ask   ───────────────► 提示用户，随后 allow / deny
        │
        ▼
   审计账本（只追加 JSONL，已脱敏，带 policyVersion 标记）
```

## 治理层能力

| 能力 | 说明 |
| --- | --- |
| 策略版本化 | 有效策略的内容哈希，附加在每个决策上，可追溯、可对比 |
| 审计 | 只追加的决策账本，带密钥脱敏；`/audit` 可查看最近决策或导出为文件 |
| 离线仿真 | 决策矩阵、规则覆盖率、死规则检测、两个策略版本之间的决策 diff |

## Bash 子命令规则

精确的 bash 模式仍然是精确匹配（`"git status"` 只匹配 `git status`）。若要**无论参数如何**
都对某个子命令设卡，在模式前加上 `cmd:`：

```jsonc
{
  "bash": {
    "git *": "ask",
    "cmd:git push": "deny",
    "cmd:git status": "allow"
  }
}
```

`cmd:git push` 匹配 `git push`、`git push --force origin main`、`FOO=bar git push`、
`/usr/bin/git push` 以及 `git.exe push`；不匹配 `git status`、`git pushx` 或 `echo git push`。
这些规则与其他 bash 规则参与同一套 last-match-wins 排序，因此先声明更宽泛的通配规则，
后声明更具体的 `cmd:` 规则。

## 安装

```bash
pi install git:github.com/<you>/pi-policy-gate
```

或从本地检出安装：

```bash
git clone https://github.com/dre4m1nd/pi-policy-gate.git
cd pi-policy-gate
bun install
pi install .
```

扩展注册了两个斜杠命令：

- `/permission-system` —— 配置调试日志与 yolo 模式行为。
- `/audit` —— 查看最近的决策，或用 `/audit export <path>` 将其写为 JSONL，供 CI 或事后审查。

## 三大支柱

### 1. 策略版本化

`src/policy-version.ts` 计算**有效**策略（全局、项目、代理、项目-代理权限分层合并后的结果）
的一段短 SHA-256 内容哈希。规范形式会按键对每个规则映射排序，因此同一套规则无论文件格式
或键顺序如何，总能得到同一个版本号。任何有效规则的变化都会改变版本号。

每条审计记录都带有产生它的版本，因此决策可追溯。`diffPolicies()` 生成两个版本之间
人类可读的增/删/改报告。

### 2. 审计决策账本

`src/audit-ledger.ts` 每个决策追加一行 JSONL 到 `~/.pi/agent/audit/decisions-<date>.jsonl`。
每条记录包含策略版本、工具、来源、命中的规则、决策，以及**已脱敏**的主体（命令或资源）。
脱敏针对常见凭证形态（厂商密钥、bearer token、key=value 秘密、长不透明令牌），
同时保留普通命令与路径不变。

设计保证：账本是**副作用**。决策绝不会因为日志失败而被阻塞或改写——缺少记录意味着决策路径
没有走到账本，而不是日志被静默跳过。

### 3. 策略仿真器

`src/policy-simulator.ts` 与 `scripts/policy-simulator.ts` 用一份固定语料
（`samples/policy-corpus.json`）对某个策略求值，并报告：

- **决策矩阵** —— 每个样本的预期决策与实际决策。
- **规则覆盖率** —— 每条规则被触发的次数。
- **死规则** —— 从未匹配任何样本的规则（写了但从不生效）。`defaultPolicy` 条目被排除：
  它们是兜底语义，不是需要被触发的规则。
- **决策差异** —— 哪些样本在两个策略之间改变了决策，因此策略编辑不会悄悄把 allow
  翻成 deny（或反过来）。

```bash
# 用参考策略跑参考语料
bun run simulate

# 比较两个策略
bun scripts/policy-simulator.ts --policy policy-a.jsonc --base ./policy-b-dir
```

## 工程决策

| 问题 | 决策 | 理由 |
| --- | --- | --- |
| 配置解析错误 | **fail-closed**：回退为 `ask` | 一条坏掉的策略不能悄悄放行一切。 |
| 规则冲突 | **last-match-wins**（来自基础版） | 保留基础版经过验证的语义；仿真器会暴露后置规则覆盖前置规则的情形。 |
| 审计写入失败 | **不影响决策**，记录警告 | 闸门绝不能因为日志不可用而被绕过。 |
| 正则注入 | 模式长度上限 + 转义（来自基础版） | 过大或不受信任的模式不会造成灾难性回溯。 |
| 死规则检测 | 排除 `defaultPolicy` | 默认值是兜底，不是需要“被触发”的规则。 |
| 脱敏 | 保守、定向 | 移除凭证形态，而不破坏普通命令/路径。 |

## 目录结构

```
src/
  policy-version.ts     规范策略 + 内容哈希 + 差异
  policy-pipeline.ts    纯的 resolve → evaluate → decide 管线
  audit-ledger.ts       只追加的决策账本 + 脱敏
  audit-command.ts      /audit 命令处理器
  bash-command.ts       cmd: 子命令规则编译器
  policy-simulator.ts   离线仿真、覆盖率、死规则、差异
  permission-manager.ts 求值内核（来自基础版；+ getEffectivePolicy）
  index.ts              扩展接线：tool_call 闸门 + 命令
samples/
  policy-corpus.json    参考决策语料
scripts/
  policy-simulator.ts   仿真器 CLI 运行器
tests/                  单元测试 + 表驱动回归测试
```

## 测试

```bash
bun install
bun run typecheck
bun run test        # 完整测试套件
bun run simulate    # 离线策略回归
```

测试套件包含针对每个新模块的表驱动测试（策略版本化、审计脱敏/账本、求值管线、仿真器）。

> 说明：`tests/config-preservation-red.test.ts` 是 Issue #31 的回归套件。其中的符号链接
> 保留用例在平台无法创建文件符号链接时会被显式跳过（Windows 未开启开发者模式 / 未提权时，
> `symlinkSync` 会抛出 `EPERM`）；在 Linux 与 macOS 上该用例会实际运行并通过，
> 确认通过符号链接形式的 `config.json` 保存会写入目标文件，并保持链接本身完好。

## 许可

MIT。部分求值内核派生自 [pi-permission-system](https://github.com/MasuRii/pi-permission-system)（© MasuRii，MIT），已保留其版权与许可声明。
