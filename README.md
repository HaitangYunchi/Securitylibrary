# SecurityLibrary.dll 使用手册

首先程序集引用 SecurityLibrary.dll 并在程序中引用 using SecurityLibrary;

如果使用中报错，请使用相同的方式引用 Newtonsoft.Json.dll

安全文件固定名称：Seccurity.enc

新增:验证黑白名单，你可以把安全文件当做白名单是有，也可以当做黑名单使用

修改了其中调用方法，以此来方便调用，


### 实例化：

```
Security validator = new();
```
调用方法：
```
// 设置加密盐值，可以从配置文件读取更安全
Security.EncryptionKey = "你获取到的加密盐值";	
```


### 黑名单验证 返回布尔值 

用户和机器码两者填写其一即可，或者都填写也行，软件会自动识别其中一项

```
var result = validator.Blacklist(userToCheck: 你的软件用户,machineToCheck: 机器码); 
```
调用实例：
```
private void btnBlacklistValidate_Click(object sender, EventArgs e)
{
    try
    {
        // 首先检查软件是否启用
        var (_, _, isEnabled) = validator.ReadSecuritylist();
        if (!isEnabled)
        {
            MessageBox.Show("软件已被管理员禁用", "系统禁用", 
            MessageBoxButtons.OK, 
            MessageBoxIcon.Stop);
            return;
        }

        // 输入验证
        if (string.IsNullOrWhiteSpace(txtUser.Text) && string.IsNullOrWhiteSpace(txtMachine.Text))
        {
            MessageBox.Show("必须输入用户名或机器码进行验证", "输入错误", 
            MessageBoxButtons.OK, 
            MessageBoxIcon.Warning);
            return;
        }

        // 调用黑名单验证
        var result = validator.blacklist(
            userToCheck: string.IsNullOrWhiteSpace(txtUser.Text) ? null : txtUser.Text.Trim(),
            machineToCheck: string.IsNullOrWhiteSpace(txtMachine.Text) ? null : txtMachine.Text.Trim());

        if (!result.IsValid)
        {
            // 验证失败处理
            MessageBox.Show(result.Message, "验证失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
            MessageBox.Show("您的账户或设备已被禁止使用本软件\n请联系管理员获取帮助", "访问被拒绝", 
            MessageBoxButtons.OK, 
            MessageBoxIcon.Stop);
            return;
        }

        // 验证通过后的处理
        MessageBox.Show("验证通过，欢迎使用本系统", "验证成功", 
        MessageBoxButtons.OK, 
        MessageBoxIcon.Information);
        // 此处继续执行后续业务代码...
    }
    catch (Exception ex)
    {
        MessageBox.Show($"系统错误: {ex.Message}", "错误", 
        MessageBoxButtons.OK, 
        MessageBoxIcon.Error);
    }
}
```

### 白名单验证 返回布尔值 

用户和机器码两者填写其一即可，或者都填写也行，软件会自动识别其中一项

```
var result = validator.Whitelist(userToCheck: 你的软件用户,machineToCheck: 机器码); 
```
调用实例：
```
private void btnWhitelistValidate_Click(object sender, EventArgs e)
{
    try
    {
        // 首先检查软件是否启用
        var (_, _, isEnabled) = validator.ReadSecuritylist();
        if (!isEnabled)
        {
            MessageBox.Show("软件已被管理员禁用", "系统禁用", 
            MessageBoxButtons.OK, 
            MessageBoxIcon.Stop);
            return;
        }

        // 输入验证
        if (string.IsNullOrWhiteSpace(txtUser.Text) && string.IsNullOrWhiteSpace(txtMachine.Text))
        {
            MessageBox.Show("必须输入用户名或机器码进行验证", "输入错误", 
            MessageBoxButtons.OK, 
            MessageBoxIcon.Warning);
            return;
        }

        // 调用白名单验证
        var result = validator.Whitelist(
            userToCheck: string.IsNullOrWhiteSpace(txtUser.Text) ? null : txtUser.Text.Trim(),
            machineToCheck: string.IsNullOrWhiteSpace(txtMachine.Text) ? null : txtMachine.Text.Trim());

        if (!result.IsValid)
        {
            MessageBox.Show(result.Message, "验证失败", 
            MessageBoxButtons.OK, 
            MessageBoxIcon.Error);
            MessageBox.Show("您未被授权使用本系统\n请联系管理员添加您的账户或设备", "访问被拒绝", 
            MessageBoxButtons.OK, 
            MessageBoxIcon.Stop);
            return;
        }

        MessageBox.Show("验证通过，欢迎使用本系统", "验证成功", 
        MessageBoxButtons.OK, 
        MessageBoxIcon.Information);
        // 后续业务代码...
    }
    catch (Exception ex)
    {
        MessageBox.Show($"系统错误: {ex.Message}", "错误", 
        MessageBoxButtons.OK, 
        MessageBoxIcon.Error);
    }
}
```

### 读取安全文件列表 返回数组

```
var (users, machines, isEnabled) = validator.ReadSecuritylist();
```
调用实例：
```
private void LoadSecuritylist()
{
    try
    {
        var (users, machines, isEnabled) = validator.ReadSecuritylist();

        // 将读取的数据显示到对应文本框
        txtUsers.Text = string.Join(Environment.NewLine, users);
        txtMachines.Text = string.Join(Environment.NewLine, machines);
        chkEnabled.Checked = isEnabled;

        statusLabel.Text = "安全文件加载成功";
    }
    catch (Exception ex)
    {
        // 文件不存在时显示空内容，其他错误显示提示
        if (!(ex is System.IO.FileNotFoundException))
        {
            MessageBox.Show($"加载安全文件失败: {ex.Message}", "错误", 
            MessageBoxButtons.OK, 
            MessageBoxIcon.Warning);
        }
        statusLabel.Text = "未发现安全文件！";
    }
}
```

### 生成安全文件

```
 bool success = validator.GenerateSecuritylist(AllowedUsers: 用户数组,
                AllowedMachines: 机器码数组,
                enableSoftware: 是否启用);
```
调用实例：
```
private void btnGenerate_Click(object sender, EventArgs e)
{
    // 处理用户输入 - 按行分割并去除空白项
    var users = txtUsers.Text.Split(new[] { Environment.NewLine }, 
    StringSplitOptions.RemoveEmptyEntries)
        .Select(u => u.Trim())
        .Where(u => !string.IsNullOrEmpty(u))
        .ToArray();

    var machines = txtMachines.Text.Split(new[] { Environment.NewLine }, 
    StringSplitOptions.RemoveEmptyEntries)
        .Select(m => m.Trim())
        .Where(m => !string.IsNullOrEmpty(m))
        .ToArray();

    // 调用DLL生成安全文件
    bool success = validator.GenerateSecuritylist(
        AllowedUsers: users,
        AllowedMachines: machines,
        enableSoftware: chkEnabled.Checked);

    // 显示操作结果
    if (success)
    {
        statusLabel.Text = "安全文件生成成功";
        MessageBox.Show($"安全文件生成成功!{Environment.NewLine}文件已保存为 Seccurity.enc","成功", 
        MessageBoxButtons.OK, 
        MessageBoxIcon.Information);
    }
    else
    {
        statusLabel.Text = "安全文件生成失败";
        MessageBox.Show("安全文件生成失败","错误", 
        MessageBoxButtons.OK, 
        MessageBoxIcon.Error);
    }
}
```