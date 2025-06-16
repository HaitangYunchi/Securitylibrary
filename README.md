# SecurityLibrary.dll 使用手册

首先程序集引用 SecurityLibrary.dll 并在程序用 using SecurityLibrary;
如果使用中报错，请使用相同的方式引用 Newtonsoft.Json.dll
安全文件名位固定名称：Seccurity.enc

实例化：
Security validator = new();

调用方法：
Security.EncryptionKey = "你获取到的加密盐值";	//	设置加密盐值

//验证 返回布尔值 用户和机器码两者填写其一即可，或者都填写也行，软件会自动识别其中一项
var result = validator.Validate(userToCheck: 你的软件用户,machineToCheck: 机器码); 

调用实例：
private void btnValidate_Click(object sender, EventArgs e)
{
    // 输入验证
    if (string.IsNullOrWhiteSpace(txtUser.Text) && string.IsNullOrWhiteSpace(txtMachine.Text))
    {
        MessageBox.Show("请输入验证信息", "提示",MessageBoxButtons.OK, MessageBoxIcon.Warning);
        return;
    }

    var result = validator.Validate(
        userToCheck: txtUser.Text,
        machineToCheck: txtMachine.Text);           
    // 如果验证失败，退出程序
    if (!result.IsValid)
    {
        MessageBox.Show(result.Message, result.IsValid ? "验证通过" : "验证失败", MessageBoxButtons.OK, result.IsValid ? MessageBoxIcon.Information : MessageBoxIcon.Error);
        MessageBox.Show("此处是验证不通过或者管理员禁用这个软件时才看到的后续程序\n验证程序可以在软件启动时加载", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        return;
        Application.Exit();   // 如果禁止后自动退出软件,请注释掉上面的return
    }
    MessageBox.Show("此处是验证通过后的后续执行代码，验证程序可以在软件启动时加载。", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
}

//读取安全文件列表 返回数组
var (users, machines, isEnabled) = validator.ReadSecuritylist();

调用实例：
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
            MessageBox.Show($"加载安全文件失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        statusLabel.Text = "未发现安全文件！";
    }
}

// 生成安全文件
 bool success = validator.GenerateSecuritylist(disabledUsers: 用户数组,disabledMachines: 机器码数组,enableSoftware: 是否启用);

 调用实例：
 private void btnGenerate_Click(object sender, EventArgs e)
{
    // 处理用户输入 - 按行分割并去除空白项
    var users = txtUsers.Text.Split(new[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries)
        .Select(u => u.Trim())
        .Where(u => !string.IsNullOrEmpty(u))
        .ToArray();

    var machines = txtMachines.Text.Split(new[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries)
        .Select(m => m.Trim())
        .Where(m => !string.IsNullOrEmpty(m))
        .ToArray();

    // 调用DLL生成安全文件
    bool success = validator.GenerateSecuritylist(
        disabledUsers: users,
        disabledMachines: machines,
        enableSoftware: chkEnabled.Checked);

    // 显示操作结果
    if (success)
    {
        statusLabel.Text = "安全文件生成成功";
        MessageBox.Show($"安全文件生成成功!{Environment.NewLine}文件已保存为Seccurity.enc",
            "成功", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }
    else
    {
        statusLabel.Text = "安全文件生成失败";
        MessageBox.Show("安全文件生成失败",
            "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
    }
}
