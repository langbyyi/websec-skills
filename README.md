# websec-skills

Web 安全漏洞测试技能集，包含 44 个漏洞类型的攻击 Playbook，用于 AI Agent 辅助安全测试。

## 技能列表

| 类别 | 技能 | 说明 |
|------|------|------|
| **注入类** | [sqli](sqli/) | SQL 注入 |
| | [nosql-injection](nosql-injection/) | NoSQL 注入 |
| | [command-injection](command-injection/) | 命令注入 |
| | [xpath-injection](xpath-injection/) | XPath 注入 |
| | [ldap-injection](ldap-injection/) | LDAP 注入 |
| | [expression-language](expression-language/) | EL/SpEL/OGNL 表达式注入 |
| | [ssti](ssti/) | 服务端模板注入 |
| | [xxe](xxe/) | XML 外部实体注入 |
| | [csv-injection](csv-injection/) | CSV/电子表格公式注入 |
| | [crlf-injection](crlf-injection/) | CRLF 注入 |
| **前端安全** | [xss](xss/) | 跨站脚本 |
| | [csrf](csrf/) | 跨站请求伪造 |
| | [clickjacking](clickjacking/) | 点击劫持 |
| | [cors](cors/) | CORS 跨域配置错误 |
| | [prototype-pollution](prototype-pollution/) | 原型链污染 |
| **认证与会话** | [authentication-bypass](authentication-bypass/) | 认证绕过 |
| | [jwt-attacks](jwt-attacks/) | JWT 攻击 |
| | [oauth-oidc](oauth-oidc/) | OAuth/OIDC 配置错误 |
| | [saml-attacks](saml-attacks/) | SAML SSO 攻击 |
| | [idor](idor/) | 越权访问 |
| **服务端漏洞** | [ssrf](ssrf/) | 服务端请求伪造 |
| | [file-upload](file-upload/) | 文件上传漏洞 |
| | [path-traversal](path-traversal/) | 路径遍历 |
| | [deserialization](deserialization/) | 反序列化漏洞 |
| | [race-condition](race-condition/) | 竞态条件 |
| | [request-smuggling](request-smuggling/) | HTTP 请求走私 |
| | [business-logic](business-logic/) | 业务逻辑漏洞 |
| | [source-code-exposure](source-code-exposure/) | 源码/配置泄露 |
| | [unauthorized-access](unauthorized-access/) | 未授权访问 |
| **API 安全** | [api-security](api-security/) | API 安全入口 |
| | [graphql](graphql/) | GraphQL 安全测试 |
| | [websocket](websocket/) | WebSocket 安全测试 |
| | [hpp](hpp/) | HTTP 参数污染 |
| **Web 基础设施** | [cache-deception](cache-deception/) | Web 缓存欺骗/投毒 |
| | [open-redirect](open-redirect/) | 开放重定向 |
| | [dependency-confusion](dependency-confusion/) | 依赖混淆 |
| | [jndi-injection](jndi-injection/) | JNDI 注入 |
| | [type-juggling](type-juggling/) | PHP 类型混淆 |
| | [xslt-injection](xslt-injection/) | XSLT 注入 |
| **移动安全** | [mobile-security](mobile-security/) | Android/iOS 安全测试 |
| **工具与侦察** | [burp-mcp](burp-mcp/) | Burp Suite MCP 自动化 |
| | [recon-and-methodology](recon-and-methodology/) | 侦察与方法论 |
| | [cyberstrike-eino-demo](cyberstrike-eino-demo/) | CyberStrike Eino 满配示例技能包 |

## 使用方式

每个技能目录下的 `SKILL.md` 是主要入口文件，可直接加载到 AI Agent 中使用。

## License

MIT
