
数据库init
docker run -dt --name mysql-homekit -e MYSQL_ROOT_PASSWORD=nlhomekit --net=host  mysql:latest
ALTER USER 'root'@'%' IDENTIFIED WITH mysql_native_password BY 'nlhomekit';
create database homekit character set utf8; 

接口清单：

    用户模块:
        1.发送验证码邮件
            sendCodeByEmail 
            入参：username
        2.注册接口
            register 
            入参(必填)：username  checkCode password
            入参(可选)：first_name last_name email avatar
            出参 ：sessionToken
        3.usersme接口
            become
        4.重置密码接口
            resetPassword
            入参(必填)：username  checkCode password
        5.修改个人信息接口
            modifyUserInfo
            入参(可选)：first_name last_name email avatar password defaultGroupId
        6.文件token接口
        7.登录接口
        8.项目增删改查  Group
        9.邀请用户 
            校验码生成 createInviteCode 
               入参 groupId
            校验码加入 joinGroup 
               入参 checkCode 
        10.分组用户管理
    业务模块：
        1.空间增删改查
        2.位置增删改查
        3.物品增删改查
        4.备注增删改查
        5.标记增删改查
        6.动态查


