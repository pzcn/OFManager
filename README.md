
# OFManager

实现 oaifree 以及 fuclaude 的用户管理

## 如何运行

1. 安装依赖：
    ```bash
    npm install
    ```

2. 运行项目：
    ```bash
    node app.js
    ```
    默认情况下，项目将运行在 3000 端口。

    如果需要运行在其他端口，例如 3456 端口，可以使用以下命令：
    ```bash
    node app.js 3456
    ```

3. 打开浏览器并访问：
    ```
    http://localhost:3000
    ```
    或者如果使用了其他端口，访问：
    ```
    http://localhost:<PORT>
    ```

## 已经实现功能

- 用户注册、登录、邀请码生成
- 渠道管理
- Fuclaude 的跳转

## 下一步实现功能

- [ ] oaifree 的跳转
- [ ] oaifree 的 token 管理
- [ ] 用量统计
- [ ] 页面优化
- [ ] 登录系统优化
- [ ] ...

## 贡献

欢迎贡献和提出建议！

## 许可证

MIT
