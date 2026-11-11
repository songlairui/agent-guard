# agent-guard

> Keep the machine usable while AI agents run it. One ops board, seven sustained
> checks, and a reaper that only kills what nobody is talking to.

AI coding agents and browser automation are extremely good at one thing nobody
asked for: leaving the machine unusable. A script that launches a headless
browser and dies on an error leaves a software-rasterized Chrome burning a dozen
cores for half a day. An indexer wanders into a node_modules tree and reads 854 TB
over two weeks. A client leaks one Wayland keymap fd per keystroke until it holds
82% of its descriptor limit.

None of that produces a useful error. All of it is invisible until the computer
stops feeling like a computer. `agent-guard` watches for exactly that shape of
failure — **sustained waste, invisible to everyone** — and puts it on one board
instead of a chat channel.

## 它解决什么

| 症状 | 之前 | agent-guard |
|---|---|---|
| agent 留下的孤儿 headless 浏览器 | 占 15/20 核跑 12 小时没人发现 | 10 分钟一次采样内识别，验证后自动清理 |
| 索引器/脚本死循环读盘 | 单进程读数 TB 级 | 单次采样读 >20 GiB 即告警 |
| Wayland/浏览器 fd 泄漏 | 悄悄吃掉 50,000 个 fd、逼近上限 | 按继承链聚合成一条告警 |
| 一进程常驻 3 核 | 只有 `top` 里一闪而过 | 连续 2 次采样仍超阈值才说话 |
| 告警噪声 | 每条都推飞书，最后没人看 | 看板全量呈现，聊天只升级「严重且未认领」 |

## 三条设计底线

1. **采样算差值，不看生命周期均值。** `ps` 的 `%CPU` 是进程一生平均，正好掩盖
   「刚烧起来」和「烧了 12 小时」的区别。这里用 `/proc/<pid>/stat` 的 utime+stime
   差值配合真实间隔算瞬时占用。
2. **持续才算异常。** 每条规则都可配置「连续 N 次采样」。编译、构建、批量转换本来
   就会短暂吃满核，那不是事故。
3. **动手术要有护栏，且要留痕。** 自动处置目前只有一类：孤儿 headless 浏览器。
   执行前逐条复核 6 项条件（见下），每次拒绝也记成一条动作，看板上能看见
   「为什么没杀」。

## 快速开始

无需任何第三方依赖（Python ≥ 3.11 标准库），Linux 直接读 `/proc`：

```bash
git clone <repo> agent-guard && cd agent-guard
python3 -m agent_guard.cli doctor        # 平台能力自检
python3 -m agent_guard.cli tick --dry-run  # 看一次采样会报什么（绝不动手）
python3 -m agent_guard.cli tick          # 采样 + 判定 + 处置 + 落库
python3 -m agent_guard.cli serve --ticker # 看板 http://127.0.0.1:7788/
```

装成用户级服务（推荐，采样和看板分开，看板挂了不影响巡检）：

```bash
./deploy/install.sh          # 生成并启用 agent-guard.tick.timer + agent-guard.board.service
systemctl --user list-timers | grep agent-guard
journalctl --user -u agent-guard.tick -f
```

## 规则

每次采样（默认 10 分钟）跑一遍以下检查。`ticks` 是「连续几次采样才触发」。

| 规则 | 触发条件 | 默认 ticks | 严重度 |
|---|---|---|---|
| `cpu_hog` | 单进程瞬时 CPU ≥ 300%（3 核） | 2 | critical |
| `load` | load1 ≥ 2 × 核数 | 2 | warn |
| `pressure` | PSI CPU `some avg300` ≥ 50% | 1 | warn |
| `io` | 单进程单次采样读 ≥ 20 GiB | 1 | warn |
| `fd` | 进程 fd ≥ 自身 soft limit 75%（≥2000 个） | 1 | warn |
| `mem` | 内存占用 ≥ 92% | 2 | warn |
| `orphan` | headless 浏览器驱动已死、存活 ≥ 300 秒 | 1 | critical |

fd 规则按**继承链**聚合：子进程整表复制父进程的 fd，一个泄漏会同时出现在十个进程上，
只报链条最上游那一条，并注明有几个进程在共享。

## 自动处置的六道护栏

只有 `orphan` 规则能触发动作，且执行瞬间逐条复核：

1. **comm 必须是已知浏览器**（chrome / chromium / headless_shell …）。带 `--headless`
   的守护进程不是浏览器 —— 这条护栏来自一次真实事故：早期版本把一个用户服务的
   `ducter up --headless` 当浏览器杀了。
2. **uid 必须是自己**，永不跨用户。
3. **命令行必须像自动化**：有 `--headless` 且另有 `--user-data-dir` 或调试端口。
   人自己开的 Chrome 不带这些，所以永远不在射程内。
4. **没有存活的调试客户端**：`--remote-debugging-port` 上还有连接就不动。
5. **不是 systemd 服务的 MainPID**：`.scope` 只是分组，不算被托管；`.service` 且
   该 pid 就是 MainPID 才跳过。
6. **父进程仍然不在**：驱动可能在采样与处置之间回来了。

每次行动（清理或拒绝）都写入 `actions` 表，看板「最近动作」可见；拒绝会写明理由。

## 告警升级：看板免费，聊天收费

```jsonc
{
  "escalation_enabled": false,               // 默认关：只看板，不推聊天
  "escalation_command": "lark-cli im +messages-send --as bot --user-id ou_xxx --markdown {message}",
  "escalate_severities": ["critical"],
  "escalate_after_unacked_seconds": 1800,    // 严重告警 30 分钟没人认领才升级
  "escalate_cooldown_seconds": 21600
}
```

被升级过的告警会在看板上标「已升级」；在页面上点「认领」即停止后续升级。
一个每 tick 都响的频道等于没有频道，所以默认策略是：**看板全量，聊天只挑严重且没人管的。**

## 配置

默认值写在 `agent_guard/config.py`，覆盖写在 `~/.config/agent-guard/config.json`：

```bash
python3 -m agent_guard.cli init-config    # 导出全部默认值
```

状态（SQLite）在 `~/.local/state/agent-guard/agent-guard.db`。

## 平台支持

| 平台 | 进程采样 | fd / IO / PSI |
|---|---|---|
| Linux | 完整（`/proc`） | 完整 |
| macOS / 其它 POSIX | `ps` 兜底，CPU 无差值精度 | 跳过 / 降级 |

`doctor` 会打印本机能力；非 Linux 主机不会假装看到 fd 和 IO。

## 为什么不用现成的

- **`systemd-oomd` / 内核 OOM**：会保命，但只在已经要死的时候动手，且不看「谁在白白浪费
  15 核」。它管内存，不管算力。
- **Prometheus + node_exporter + Alertmanager**：能表达这些问题，但一台个人机器为了
  抓三个进程要跑三套服务、写一堆 YAML，还要自己配通知去噪。这里要的是
  `git clone && 跑起来`。
- **`top` / `htop` / `btop`**：让人看见当下，但没人盯着；而这批问题的共同点正是
  「没人盯着，且不报错」。

## 路线

- [x] 采样 / 七条规则 / 继承链聚合 / 看板 / 升级策略
- [x] 孤儿浏览器自动处置 + 六道护栏 + 行动审计
- [x] SQLite 事件时间线、认领与冷却
- [ ] 规则热加载与每规则独立阈值文件（YAML）
- [ ] 检测「agent 会话级」浪费：按 cgroup / 会话归集开销，而不是按进程
- [ ] macOS 的 fd 与 IO 采样（`libproc` / `lsof`）
- [ ] 看板历史导出（JSONL / 截图）与多机聚合
- [ ] 把「本次 AI 会话让机器多付了多少」做成一张账单

## 许可

MIT。

## 出处

在 `merge-pilot` 一次真实的排查中长出来：四个孤儿 headless Chrome 吃掉 20 核里的
12 核、`localsearch-3` 连续 13 天读了 854 TB、quickshell 泄漏 50,654 个 Wayland keymap
fd。三次都是「机器变慢、日志干净、没人知道」。这个项目就是那三次的产物。