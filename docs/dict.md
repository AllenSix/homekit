##数据字典


###表目录
- User   用户表
- Group  分组表
- GroupUser 用户分组表
- Space  空间表
- Position  位置表
- Goods  物品表
- Notes 备注表
- Marks 标注表
- News  动态表

###云函数目录
- sendCodeByEmail	 发送验证码邮件
- queryEmail    查询邮箱是否已存在
- register	注册
- resetPassword	重置密码
- modifyUserInfo	修改用户信息
- createInviteCode	创建邀请码
- joinGroup	加入分组
- readNews  标记或关闭

----------
###用户表
####表名称
User
####描述
用户表
####字段说明

|名称|类型|说明|缺省|
|-|-|-|-|
|firstName |string|用户名| 无|
|lastName |string|用户姓| 无|
|username |string|帐号名| 无|
|email |string|邮箱| 无|
|checkCode |string|验证码| 无|
|password |string|密码 | 无|
|defaultGroupId |int|默认分组ID | 无|
|avatar |string|头像地址| 无|
|sessionToken |string|登录session| 无|
|isDisable |boolean|禁用标志 1-禁用| 无|


----------

###分组表
####表名称
Group
####描述
分组表 前端可操作 增删查
####字段说明

|名称|类型|说明|缺省|
|-|-|-|-|
|name |string|分组名称| 无|
|avatar |string|头像地址| 无|
|desc |string|分组描述| 无|
|belongUserId |int|所属用户ID | 无|
|isPublic |boolean|是否公开 1-公开| 0|
|checkCode |string|密码 | 无|
|isDisable |boolean|禁用标志 1-禁用| 无|


----------

###分组用户关联表
####表名称
GroupUser
####描述
分组用户关联表
####字段说明

|名称|类型|说明|缺省|
|-|-|-|-|
|userId |int|用户ID| 无|
|groupId |int|分组ID| 无|
|isDisable |boolean|禁用标志 1-禁用| 无|
|isAudit |boolean|审核标志 1 通过| 无|

----------
###空间表
####表名称
Space 前端可操作 增删查
####描述
空间表
####字段说明

|名称|类型|说明|缺省|
|-|-|-|-|
|name |string|空间名| 无|
|avatar |string|图片地址| 无|
|belongUserId |int|所属用户ID | 无|
|belongGroupId |int|所属分组ID| 无|
|isPublic |boolean|是否公开 1-公开| 0|
|isDisable |boolean|禁用标志 1-禁用| 无|

----------
###位置表
####表名称
Position
####描述
位置表 前端可操作 增删查
####字段说明

|名称|类型|说明|缺省|
|-|-|-|-|
|name |string|空间名| 无|
|avatar |string|图片地址| 无|
|belongUserId |int|所属用户ID | 无|
|belongGroupId |int|所属分组ID| 无|
|spaceId |int|空间ID | 无|
|coordinate |string|坐标位置| 无|
|isPublic |boolean|是否公开 1-公开| 0|
|isDisable |boolean|禁用标志 1-禁用| 无|

----------
###物品表
####表名称
Goods
####描述
物品表 前端可操作 增删查
####字段说明

|名称|类型|说明|缺省|
|-|-|-|-|
|name |string|空间名| 无|
|avatar |string|图片地址| 无|
|belongUserId |int|所属用户ID | 无|
|belongGroupId |int|所属分组ID| 无|
|spaceId |int|空间ID | 无|
|positionId |int|位置ID | 无|
|coordinate |string|坐标位置| 无|
|isPublic |boolean|是否公开 1-公开| 0|
|isDisable |boolean|禁用标志 1-禁用| 无|


----------
###备注表
####表名称
Notes
####描述
备注表 前端可操作 增删查
####字段说明

|名称|类型|说明|缺省|
|-|-|-|-|
|note |string|备注| 无|
|belongUserId |int|所属用户ID | 无|
|belongGroupId |int|所属分组ID| 无|
|spaceId |int|空间ID | 无|
|positionId |int|位置ID | 无|
|goodsId |int|物品ID | 无|
|isPublic |boolean|是否公开 1-公开| 0|
|isDisable |boolean|禁用标志 1-禁用| 无|


----------
###标记表
####表名称
Marks
####描述
标记表 前端可操作 增删查
####字段说明

|名称|类型|说明|缺省|
|-|-|-|-|
|belongUserId |int|所属用户ID | 无|
|belongGroupId |int|所属分组ID| 无|
|spaceId |int|空间ID | 无|
|positionId |int|位置ID | 无|
|goodsId |int|物品ID | 无|
|isPublic |boolean|是否公开 1-公开| 0|
|isDisable |boolean|禁用标志 1-禁用| 无|

----------
###动态表
####表名称
News
####描述
动态表 前端可操作 查
####字段说明

|名称|类型|说明|缺省|
|-|-|-|-|
|title |string|标题 | 无|
|content |string|内容（备注） | 无|
|type |int|动态类型 1-添加物品 2-标记物品 3-备注 4-新建位置| 无|
|avatar |string|图片地址| 无|
|belongUserId |string|所属用户ID | 无|
|belongGroupId |string|所属分组ID| 无|
|spaceId |int|空间ID | 无|
|positionId |int|位置ID | 无|
|goodsId |int|物品ID | 无|
|isPublic |boolean|是否公开 1-公开| 0|
|isDisable |boolean|禁用标志 1-禁用| 无|


----------
###帮助地址
####表名称
Helps
####描述
帮助地址表
####字段说明

|名称|类型|说明|缺省|
|-|-|-|-|
|url |string|地址| 无|

----------
###发送验证码邮件
####方法名称
sendCodeByEmail
####描述
发送验证码邮件
####输入说明
|----|----|
|名称|类型|说明|缺省|
|username |string|帐号名| 无|

####输出说明
无，判断调用是否成功即可，如错误进行提示

####数据示例
    {"result": {"error_code": 0, "msg": 'succ'}}
    

----------
###查询邮箱帐号是否存在
####方法名称
queryEmail
####描述
查询邮箱帐号是否存在
####输入说明
|----|----|
|名称|类型|说明|缺省|
|username |string|帐号名| 无|

####输出说明
无，判断调用是否成功即可，如错误进行提示

####数据示例
    {"result": {"error_code": 0, "msg": 'succ'}}

----------
###注册接口
####方法名称
register
####描述
注册接口
####输入说明
|----|----|
|名称|类型|说明|缺省|
|username |string|帐号名 必填| 无|
|checkCode |string|验证码 必填| 无|
|password |string|密码 必填| 无|
|first_name |string|用户名 | 无|
|last_name |string|用户姓 | 无|
|email |string|邮箱地址 | 无|
|avatar |string|头像地址 | 无|

####输出说明
|sessionToken |string|用户session | 无|


####数据示例
    {"result": {
        "data": {"sessionToken": user.sessionToken}, "error_code": 0, "msg": "注册成功"}}
        
----------
###重置密码接口
####方法名称
resetPassword
####描述
重置密码接口
####输入说明
|----|----|
|名称|类型|说明|缺省|
|username |string|帐号名 必填| 无|
|checkCode |string|验证码 必填| 无|
|password |string|密码 必填| 无|

####输出说明
无，判断调用是否成功即可，如错误进行提示

####数据示例
    {"result": {"error_code": 0, "msg": 'succ'}}
    

----------
###修改用户信息接口
####方法名称
modifyUserInfo 必须登录
####描述
修改用户信息接口
####输入说明
|----|----|
|名称|类型|说明|缺省|
|password |string|密码 可选| 无|
|first_name |string|用户名 可选| 无|
|last_name |string|用户姓 可选| 无|
|email |string|邮箱地址 可选| 无|
|avatar |string|头像地址 可选| 无|
|defaultGroupId |int|默认分组ID  可选| 无|

####输出说明
无，判断调用是否成功即可，如错误进行提示

####数据示例
    {"result": {"error_code": 0, "msg": 'succ'}}
    
----------
###校验码生成
####方法名称
createInviteCode
####描述
校验码生成 必须登录
####输入说明
|----|----|
|名称|类型|说明|缺省|
|groupId |int|分组ID 必填| 无|

####输出说明
|checkCode |string|分组邀请码 | 无|

####数据示例
    {"result": {"data": {"checkCode": group.checkCode}, "error_code": 0, "msg": "邀请码创建成功"}}
    
----------
###加入分组
####方法名称
joinGroup
####描述
加入分组
####输入说明
|----|----|
|名称|类型|说明|缺省|
|checkCode |string|分组邀请码 必填| 无|

####输出说明
无，判断调用是否成功即可，如错误进行提示

####数据示例
    {"result": {"error_code": 0, "msg": 'succ'}}
    

----------
### 标记/关闭
####方法名称
readNews
####描述
标记/关闭
####输入说明
|----|----|
|名称|类型|说明|缺省|
|isMark |int|0-关闭 1-标记| 无|
|newsId |int|动态ID | 无|

####输出说明
无，判断调用是否成功即可，如错误进行提示

####数据示例
    {"result": {"error_code": 0, "msg": 'succ'}}