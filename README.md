# spark-initiative-backend

OS Camp 2026 的极简仓库领取服务。它只做 GitHub Classroom 中仍然需要的部分：学员登录 GitHub，然后为 Rust 和 rCore 各领取一个组织内仓库。

它不负责课程内容、CI、评分或排行榜。现有 `os_camp_be` 继续独立扫描 GitHub 仓库；两个服务不调用彼此，也不共享数据表。

## 行为

| 阶段 | 模板 | 生成的仓库名 | 分支 |
| --- | --- | --- | --- |
| Rust | `rustling-2026-template` | `rcore-rustlings-2026-{login}` | 默认分支 |
| rCore | `rCore-Camp-Code-2026` | `rcore-camp-2026-{login}` | 全部分支 |

领取是同步操作：

1. 在 MySQL 中占用 `(GitHub 数字 ID, 阶段)`。
2. 用 GitHub template API 生成公开仓库。
3. 给领取时的 GitHub login 授予 `push` 权限。
4. 将仓库和邀请链接写回同一条领取记录。

没有 worker、队列或后台任务。GitHub 暂时失败时接口返回可重试错误；重试使用相同仓库名。若上一次生成成功但响应丢失，服务会按仓库名和 description marker 找回仓库。已经完成的领取直接从 MySQL 返回，不再请求 GitHub。

已完成的仓库可以重新创建。若 GitHub 上的原仓库仍存在，服务会先核对仓库 ID、名称和 description marker，再删除并从模板重建；若原仓库已经删除，则直接重建。成功后，新的仓库 ID、地址和邀请链接会覆盖原领取记录。

## HTTP 接口

所有路径都位于 `/api/classroom/v1`：

- `GET /auth/login`
- `GET /auth/callback`
- `POST /auth/logout`
- `GET /state`
- `POST /claim/rust`
- `POST /claim/rcore`
- `POST /claim/rust/recreate`
- `POST /claim/rcore/recreate`

`GET /state` 返回当前用户、阶段开关、领取结果和 `csrf_token`。所有 POST 接口都需要同源 `Origin` 和 `X-CSRF-Token`，领取及重新创建接口的 body 必须为空。

OAuth state、PKCE verifier 和 30 分钟登录会话都保存在签名、`Secure`、`HttpOnly`、`SameSite=Lax` Cookie 中。GitHub user token 只用于读取 `/user`，不会保存。

## MySQL

服务只创建并使用 `spark_repo_claims`。可以与排行榜使用同一个 MySQL database；它不会读取或修改旧服务的 `phase1_user_info`、`phase2_user_info`。

部署时先由管理员执行 [schema.sql](schema.sql)。程序启动时不会修改表结构；服务账号只需要该表的 `SELECT`、`INSERT` 和 `UPDATE` 权限。

## GitHub App

创建一个 GitHub App，同时用于网页登录和组织安装：

- Repository permissions：`Administration: Read and write`
- Repository permissions：`Contents: Read-only`
- Organization / Account permissions：不需要
- Webhook：不需要
- 安装目标：`uestc-workshop-os-camp`
- Repository access：只选择两个模板仓库

Callback URL：

```text
https://csinfra.cn/api/classroom/v1/auth/callback
```

服务端固定组织、模板、仓库名前缀、公开可见性和协作者权限；浏览器不能覆盖这些值。若目标仓库已经存在但 description marker 不属于该领取记录，服务会返回冲突，不会接管或删除仓库。

## 配置与运行

服务只读取环境变量，不自行解析 `.env`。参考 [.env.example](.env.example)，至少提供 MySQL DSN、Cookie key 和 GitHub App 凭据。

生成 Cookie key：

```bash
openssl rand -base64 32
```

本地检查和构建：

```bash
go test ./...
go vet ./...
CGO_ENABLED=0 go build -trimpath -o spark-initiative-backend .
```

程序只允许监听 loopback，生产环境由同域 HTTPS Nginx 转发 `/api/classroom/v1/`。OAuth callback 的 access log 不应记录 query string，因为其中含有一次性 `code` 和 `state`。

两个阶段默认关闭。模板和邀请流程验证完毕后，分别设置：

```text
SPARK_RUST_ENABLED=true
SPARK_RCORE_ENABLED=true
```

## 与旧排行榜的契约

新服务不写排行榜数据库。兼容只依赖仓库名称：

- `rcore-rustlings-2026-` 前缀由旧服务识别为 Rust。
- `rcore-camp-2026-` 前缀由旧服务识别为 rCore。

课程模板中的 CI 继续把 `latest.json` 和成绩文本写到各仓库的 `gh-pages` 数据分支；不需要启用 GitHub Pages。
