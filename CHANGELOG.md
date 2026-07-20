# 变更日志
## [2.1.2] - 2026-07-20 14:58
### 修复
- 修复调用底层 Windows hello 时弹窗层级没有置顶的问题;
## [2.1.1] - 2026-07-18 22:29
### 优化
- 不再局限于 @flun/desktop-builder 构建的应用,只要是 Windows 环境并且可用,都优先调用底层 Windows hello;
## [2.1.0] - 2026-07-16 19:41
### 新增
- 新增支持 @flun/desktop-builder 构建的桌面应用,并且环境为Windows时,优先通过底层实现硬件验证(Windows hello),其它环境不变;