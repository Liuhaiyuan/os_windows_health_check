# os_windows_health_check
OS—— Windows 操作系统健康检查工具

## 运行方式

1. Windows 2012 （含）以上版本双击Run_WindowsCheck.bat运行，。
2. 脚本运行完成后会在脚本目录下生成Check_Report_Date.html文件及C:\check_healthsystem.evtx,security.evtx,app.evtx,setup.evtx四个日志文件

## 实现功能

1. 收集OS基本配置，通过调用powershell模块获取系统配置信息（内存，CPU，网卡，磁盘等基础配置信息）
2. 采集OS的系统、应用、更新及安全日志文件。
3. 通过注册表信息获取OS系统已经安装的软件列表
4. 获取系统已经更新的补丁包安装信息
5. 收集当前系统的网络连接信息
6. 收集系统开启的、禁用的、停止的服务列表。
7. 收集系统运行的进程使用信息