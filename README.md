# GSB Bugfix Task
## 题面
文档权限现在只看文档存不存在：别人的文档能读、跨租户能读、已删除也能读，普通用户还能进管理接口，更新时能把 owner 和 tenant 一起改掉。access_guard.py 是核心，tests/test_access_guard.py 15 个红。要修成按 owner、tenant、角色和删除状态做读写授权，管理接口只允许管理员，更新字段要有白名单，不能改 owner/tenant。修完 15 个测试后，还要保证 1000 组随机用户/文档/租户组合没有越权，32 线程并发更新不串权限；不许改测试或硬编码用户。边界至少覆盖空用户、跨租户、已删除文档、普通用户调管理接口、批量赋值改 owner。

## 运行方式
```bash
python -m pytest tests -q
```

## 平台字段

所属领域：安全
子方向：漏洞检测与攻防
任务类型：Bugfix
语言 / 框架：Python 3, pytest
环境可复现等级：无外部依赖
