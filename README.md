<p align="center">
  <img src="https://github.com/can1357/oh-my-pi/blob/main/assets/hero.png?raw=true" alt="omp">
</p>

<p align="center">
  <strong>为 USTC iWAN 校园网优化的 AI 编码代理(omp fork)</strong>
</p>

<p align="center">
  <a href="https://github.com/yorha2B0826/oh-my-pi/releases"><img src="https://img.shields.io/github/v/release/yorha2B0826/oh-my-pi?style=flat&colorA=222222&colorB=3FB950" alt="release"></a>
  <a href="https://github.com/yorha2B0826/omp-ustc"><img src="https://img.shields.io/badge/brew%20tap-omp--ustc-CB3837?style=flat&colorA=222222" alt="Homebrew tap"></a>
  <a href="https://github.com/can1357/oh-my-pi"><img src="https://img.shields.io/badge/fork%20of-can1357%2Foh--my--pi-58A6FF?style=flat&colorA=222222" alt="Fork of"></a>
  <a href="https://github.com/yorha2B0826/oh-my-pi/blob/main/LICENSE"><img src="https://img.shields.io/github/license/yorha2B0826/oh-my-pi?style=flat&colorA=222222&colorB=58A6FF" alt="License"></a>
</p>

> [!IMPORTANT]
> 本仓库是 [can1357/oh-my-pi](https://github.com/can1357/oh-my-pi) 的个人 fork,针对**中国科学技术大学 iWAN 校园网用户**做了定制优化。日常使用请安装本 fork 的发布版本(见下);想了解上游的全部特性,请访问 [omp.sh](https://omp.sh) 与上游仓库。

## 这是什么

omp(oh-my-pi)是一个把 IDE 接进来的 AI 编码代理:60+ 模型提供商、31 个内置工具、14 种 LSP 操作、28 种 DAP 操作、约 8 万行 Rust 核心。本 fork 在其基础上,为 USTC 校园网场景补齐了三件事:

1. **iWAN VPN 隧道内置集成** —— 不用再单独开 VPN 客户端,`omp iwan` 一条命令登录、连接,代理 `api.llm.ustc.edu.cn` 的模型请求
2. **USTC LiteLLM 网关模型适配** —— `api.llm.ustc.edu.cn` 动态发现模型,并按模型映射正确的上下文窗口(不再一刀切)
3. **fork 自己的发布流水线** —— 用 GitHub Actions 构建 darwin-arm64 / linux-arm64 / linux-x64 三个平台二进制,配套 Homebrew tap,`brew install` 即用

## 相比上游的改动

| 改动 | 说明 |
|---|---|
| `crates/pi-iwan/`(新) | iWAN 协议原生实现:OAuth PKCE 登录、控制器服务器发现、密码恢复、SOCKS5 隧道(crypto 在 `packages/ai/src/iwan/`,native 绑定在 `crates/pi-natives/src/iwan.rs`) |
| `omp iwan` 命令 | `login` / `connect` / `status` / `stop` / `servers` 五个子命令管理隧道 |
| 隧道自愈 | 隧道死亡检测、心跳超时、断流/分块/重试分类,断线自动重连(`socks.rs` / `fetch.ts` / `service.ts`) |
| USTC 模型上下文窗口 | `openai-compat.ts` 按模型映射 USTC 网关各模型的上下文窗口(默认 1M,细粒度修正) |
| 请求路由 | 仅 `api.llm.ustc.edu.cn` 的请求走隧道,其余流量不受影响(`iwan/route.ts`) |
| CI 裁剪 | 移除依赖 omp-kata/bazel 私有基础设施的上游 workflow,保留轻量测试 |
| 发布矩阵 | `darwin-x64`(Intel Mac)省略——GitHub 已退役 macos-13 runner;native 用 cargo backend 构建,不依赖 Bazel |
| 自动同步 | 每 3 小时自动检查上游更新 → 合并(保留全部定制)→ 本地测试(check:ts + natives + smoke)→ 推回 fork;上游发布新版本时自动触发 fork release 并联动更新 brew tap |

## 安装

### macOS(Apple Silicon)与 Linux

**Homebrew(推荐,macOS)**

```bash
brew tap yorha2b0826/omp-ustc
brew install omp
```

升级:

```bash
brew update && brew upgrade omp
```

**直接从 GitHub Release 下载**

到 [Releases](https://github.com/yorha2B0826/oh-my-pi/releases) 下载对应平台的二进制(`omp-darwin-arm64` / `omp-linux-arm64` / `omp-linux-x64`),放入 PATH 并重命名为 `omp`:

```bash
chmod +x omp-linux-x64 && sudo mv omp-linux-x64 /usr/local/bin/omp
```

### 其他方式(官方源)

本 fork 与上游保持同步,也可以使用上游的安装方式(会得到不含 iWAN 定制的版本):

```sh
curl -fsSL https://omp.sh/install | sh
# 或
bun install -g @oh-my-pi/pi-coding-agent
```

> [!NOTE]
> 想要 iWAN 集成,请务必安装本 fork 的 release(上面的两种方式),而不是上游源。

## 快速上手

### 1. 登录 iWAN 并连接隧道

```bash
omp iwan login      # 弹出浏览器完成 USTC 统一身份认证(PKCE)
omp iwan connect    # 连接 VPN,建立本地 SOCKS5 隧道
omp iwan status     # 查看隧道状态
```

连接成功后,对 `api.llm.ustc.edu.cn` 的模型请求会自动走隧道,其他流量不受影响。

```bash
omp iwan servers    # 列出可用的控制器服务器
omp iwan stop       # 断开隧道
```

> 隧道带心跳保活与死亡检测:网络抖动断线后会自动重连,无需手动干预。

### 2. 配置 USTC LLM API 并开始使用

USTC 的 LLM 网关(`api.llm.ustc.edu.cn`)是校内 LiteLLM 服务,接入方式二选一:

**方式 A:交互式登录(推荐)**

```bash
omp
/login        # 在会话内执行,选择 USTC 提供商
```

按提示 **从 USTC LLM 网关控制台复制 API key**(`sk-...`)粘贴即可。程序会用 `GET https://api.llm.ustc.edu.cn/v1/models` 自动验证 key 是否有效,并把凭据存入本地凭据库(credential vault)。

**方式 B:环境变量**

```bash
export USTC_API_KEY="sk-..."
```

> key 的获取与续期都在 USTC LLM 网关控制台完成;iWAN 隧道连接后,模型请求自动走隧道,无需其他配置。

配置好后:

```bash
omp
/model        # 模型选择器中选 ustc 提供商(自动从网关 /v1/models 动态发现)
```

`api.llm.ustc.edu.cn` 的模型列表随网关部署动态变化;本 fork 已按模型映射正确的上下文窗口(如 1M 上下文模型不再被错误截断)。

### 3. 日常使用

```bash
omp                  # 交互式会话(相当于 /model、/read、/edit 等)
omp "实现一个 LRU cache"   # 一次性任务
```

## 开发

```bash
git clone git@github.com:yorha2B0826/oh-my-pi.git
cd oh-my-pi
bun install
bun run check:ts           # 类型检查
bun --cwd=packages/natives run build   # 构建 native 绑定(需 nightly-2026-07-28)
bun run ci:test:smoke      # 冒烟测试
```

> 需要 [rustup](https://rustup.rs) 的 `nightly-2026-07-28` 工具链(`rust-toolchain.toml` 会自动切换)。

## 与上游同步

本 fork 通过 GitHub Actions + 本地 cron 每 3 小时检查上游 `can1357/oh-my-pi` 更新:

- 有新提交 → 自动合并(保留全部定制:`release-fork.yml`、`crates/pi-iwan/`、USTC 适配、iWAN 自愈)→ 跑完整测试 → 推送
- 上游发布新版本 → 自动触发 fork release 构建 → 联动更新 `omp-ustc` brew tap
- merge 冲突或测试失败时**不会强行处理**,会保留现场并通知人工介入

上游状态可随时查看:比较 [can1357/oh-my-pi:main...yorha2B0826:main](https://github.com/can1357/oh-my-pi/compare/main...yorha2B0826:main)。

## License

MIT,与上游一致。

---

*由 [can1357/oh-my-pi](https://github.com/can1357/oh-my-pi) fork 而来。上游是 [Pi](https://github.com/badlogic/pi-mono) 的续作,作者 [@mariozechner](https://github.com/mariozechner)。*
