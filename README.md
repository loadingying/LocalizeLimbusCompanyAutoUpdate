没问题，主人～我把 README 改成更小白、**不再提到 7-Zip、操作日志、也不要求设置游戏目录** 的版本了。你可以直接整段替换。

---

# Limbus Company 汉化补丁自动更新工具

这个小工具会**自动下载并安装**《Limbus Company》的最新汉化补丁（由 [零协会](https://github.com/LocalizeLimbusCompany/LocalizeLimbusCompany) 提供）。
你只需要**双击运行**，其余的它都会自己搞定。

---

## 它能做什么？

* 自动检查是否有**新版本**
* 自动**下载、解压、安装**汉化补丁
* 自动安装**所需字体**
* 支持**计划任务**：开机后自动检查更新（可选）
* **多源下载**：提高下载成功率

> **无需手动设置游戏目录** —— 程序会自动识别。

---

## 开始使用（超简单）

1. **放好文件**
   把这些文件放在同一个文件夹里：

* `auto_update.exe`（主程序）
* `Register-AutoUpdate.ps1`（注册自动更新）
* `Unregister-AutoUpdate.ps1`（取消自动更新）

2. **一键更新**
   双击运行 `auto_update.exe`，等待提示完成即可。

3. **想开机自动更新？（可选）**

* 注册：右键 `Register-AutoUpdate.ps1` → 选择“使用 PowerShell 运行”（会弹出管理员确认）
* 取消：右键 `Unregister-AutoUpdate.ps1` → “使用 PowerShell 运行”（同样会弹出确认）

> 如果运行脚本时提示“已禁用脚本执行”，请在该 PowerShell 窗口执行：
> `Set-ExecutionPolicy -Scope Process Bypass -Force`

---

## 脚本都做了什么？

* `Register-AutoUpdate.ps1` 会以管理员身份调用：

  ```
  auto_update.exe --register
  ```

  在用户登录 Windows 时自动检查更新（每天固定时间也会再检查一次）。

* `Unregister-AutoUpdate.ps1` 会以管理员身份调用：

  ```
  auto_update.exe --unregister
  ```

  取消自动更新计划任务。

---

## 系统要求

* Windows 10/11（64 位）
* 需要联网以下载补丁

---

## 致谢

感谢零协会以及所有为《Limbus Company》汉化贡献的开发者、校对与社区小伙伴们！
