# 自动化信息收集工具-Findyou

郑重声明：文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途以及盈利等目的，否则后果自行承担。

## 0x01 介绍
### 想法
分布式联想信息收集，通过公司名、域名、ip，使用备案、Hunter、FOFA及Quake等对搜索结果进行联想式收集（icp.name,domain.suffix），判断域名是否cdn，非CDNip继续结合自定义关键字如title=某某银行进行C段收集，统计ip段资产数量结合归属地进行重要ip段发现，指纹识别中自动识别供应链及可能被利用的社工钓鱼信息。

### 未实现
1. 公司名无法自动拉取子公司信息
2. 无法通过备案接口查询备案域名，仅通过hunter的icp.name查询

### 目前不足
很多模块目前比较潦草，后续有时间慢慢优化，欢迎提交代码一起优化
任务分发及数据存储目前均使用mysql+redis完成，后期可使用gorpc方便管理客户端及任务分发

## 0x02 安装使用
1. 安装mysql及redis，配置后将连接信息写入到config文件夹的app.yml中
2. 直接生成taskscheduling及workflow文件，将config文件夹放到同级目录下
3. 配置taskscheduling下config文件夹中的target.yml相关信息，运行taskscheduling，然后启动workflow即可
4. 扫描结果在mysql中findyou数据库中，HighLevelTargets为可能存在漏洞的指纹，targets为所有目标信息，SensitiveInfo为供应链及社工钓鱼信息

测试函数实现的小功能
> workflow/common/aliveandpassivityscan/aliveandpassivityscan_test.go函数中实现了直接从本地文件按行读取目标直接进行探活+指纹识别
> workflow/common/cdn/cdn_test.go函数中实现了批量识别目标是否是cdn资产


## 0x03 开发日志
2025.8.11 开源

## TODO
[ ] 添加根据公司名查询备案域名的接口，添加拉取下级公司的接口

[ ] 指纹识别被动识别结束后再主动扫描识别，避免ip被封

[ ] 调度中心和工作流模块任务状态，方便判断客户端是否正常，使用gorpc

[ ] 导出excel