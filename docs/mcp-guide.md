# 觅影 MCP 接入指南（给 AI Agent 的自助配置说明）

> 你正在阅读这份指南的用户希望你把「觅影」影视资源搜索接入到你的工具里。
> 照下面的步骤做，完成后向用户报告接入成功，并用一次测试搜索验证。
> **全程只缺一样东西：该用户在觅影站点的账号令牌（token）。没有令牌时，停下来向用户索取，不要猜、不要编造。**

## 这是什么

觅影是一个自托管的网盘影视资源检索服务。它对外提供一个标准 MCP（Model Context Protocol，Streamable HTTP）接口，只暴露一个搜索工具：给片名，返回各网盘（百度、夸克、阿里、迅雷、UC、天翼、115、123、磁力）的分享链接与提取码。只做搜索，不登录网盘、不转存、不下载。

## 接口信息

| 项 | 值 |
|---|---|
| MCP 端点 | `https://sou.vertexlab.tech/portal/mcp` |
| 传输 | Streamable HTTP，无状态（无需保存 session） |
| 鉴权 | HTTP 头 `Authorization: Bearer <token>` |
| 工具 | `search_resources`（仅此一个） |

## 第一步：取得令牌（二选一）

令牌就是站点账号的登录凭证（JWT，有效期 180 天），**按密码对待**。

- **方式 A（用户直接给令牌）**：用户把令牌发给你后，把它写入配置（见第二步），不要在对话里复述，不要写进任何公开文件或日志。
- **方式 B（用户给账号密码，你来换令牌）**：调用登录接口：

  ```bash
  curl -s -X POST "https://sou.vertexlab.tech/portal/api/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"<用户名>","password":"<密码>"}'
  ```

  返回 JSON 中的 `token` 字段即为令牌（响应还包含 `username`、`is_admin`）。换到令牌后不要保留或记录密码原文。

安全要求：
- 优先使用**普通账号**的令牌，不要用管理员账号；普通账号权限足够搜索。
- 令牌只存放在你所在 Agent 的 MCP 配置或环境变量中。
- 若令牌泄露：通知用户在站点修改该账号密码或停用该账号，旧令牌即失效。

## 第二步：写入你所在客户端的 MCP 配置

通用形式（多数支持远程 MCP 的客户端通用，按你所在客户端的配置格式等价改写，配置项名称以客户端官方文档为准）：

```json
{
  "mcpServers": {
    "miying": {
      "type": "http",
      "url": "https://sou.vertexlab.tech/portal/mcp",
      "headers": {
        "Authorization": "Bearer <token>"
      }
    }
  }
}
```

写完后按你所在客户端的要求重载配置或重启会话，使工具生效。

## 第三步：验证

调用 `search_resources` 做一次测试搜索（例如 keyword 传 `沙丘2`，limit 传 5）。能返回带 `title`、`drive`、`url` 的结果列表即接入成功。若返回 401，说明令牌无效或已过期，停下来向用户报告，不要反复重试。

没有 MCP 客户端能力时，也可以用 curl 直接走 JSON-RPC（先 initialize，再发 notifications/initialized，最后 tools/call）：

```bash
curl -s -X POST "https://sou.vertexlab.tech/portal/mcp" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_resources","arguments":{"keyword":"沙丘2","limit":5}}}'
```

## 工具说明：search_resources

| 参数 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `keyword` | string | 是 | 影视名称，可带画质要求，如 `沙丘2 4K原盘`；画质词（原盘 / REMUX / 4K / 杜比视界等）会被识别为画质提示，不会当作片名的一部分死匹配 |
| `limit` | integer | 否 | 返回条数 1–30，默认 30 |
| `drive` | string | 否 | 限定单个网盘，枚举：`quark`、`baidu`、`aliyun`、`xunlei`、`uc`、`tianyi`、`115`、`123`、`magnet`；不传返回全部网盘 |

每条结果字段：`title`（标题）、`drive`（网盘）、`url`（分享链接）、`password`（提取码，可能为空）、`source`（来源）、`datetime`（资源时间）、`year`（年份）、`rating`（豆瓣评分）、`size`（体积，上游无数据时为空）。

使用提示：
- 想要某个网盘的结果就传 `drive`，不要靠在结果里肉眼筛。
- 画质标注来自资源标题，是发布者自称、未经文件校验；年份与评分是作品级元数据。
- 搜不到时先换片名写法（简繁、带年份、带季号）再下结论，不要断言资源不存在。
