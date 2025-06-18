# SecurityLibrary.dll 使用手册

首先程序集引用 SecurityLibrary.dll 并在程序中引用 using SecurityLibrary;

如果使用中报错，请使用相同的方式引用 Newtonsoft.Json.dll

安全文件固定名称：Seccurity.enc

新增:验证黑白名单，你可以把安全文件当做白名单使用，也可以当做黑名单使用

新增：生成机器码 详情见下面说明 GenerateMachineCode()



### 首先声明实例：

```
private string secretKey;
private Security validator;
```
在主代码头部实例化：
```
secretKey = KeyManager.LoadKey();       // 你的秘钥获取方法
security = new Security(secretKey);     // 实例化安全库
```
调用实例

```
using System;
using System.ComponentModel;
using System.Linq;
using System.Management;
using System.Windows.Forms;
using SecurityLibrary;  // 程序集引用后，这里 using 引用一下

namespace MyApp
{
    public partial class From1 : Form
    {
        // 私有字段声明
        private string secretKey;       // 存储从安全存储中加载的加密密钥（核心敏感数据）
        private Security security;      // SecurityLibrary的安全验证实例（核心功能入口）

        public From1()         
        {         
            InitializeComponent();        

            // 加载加密密钥（从安全存储中获取，如配置文件、注册表或硬件保护存储）
            // KeyManager.LoadKey() 是自定义方法，具体实现可能包括：
            // - 从加密配置文件读取密钥
            // - 从Windows DPAPI保护的存储中解密获取
            // - 从硬件安全模块（HSM）或可信执行环境（TEE）中读取
            secretKey = KeyManager.LoadKey();

            // 初始化安全验证实例（传入加载的密钥）
            // Security类来自SecurityLibrary，用于后续执行黑白名单验证、机器码生成等操作
            security = new Security(secretKey);  
        }

        // 后续业务代码方法...（例如：按钮点击事件、菜单操作、核心业务逻辑等）
}
```

### 黑名单验证 返回布尔值 

用户和机器码两者填写其一即可，或者都填写也行，软件会自动识别其中一项

```
var result = seccurity.Blacklist(userToCheck: 你的软件用户,machineToCheck: 机器码); 
```
调用实例：
```
private void btnBlacklistValidate_Click(object sender, EventArgs e)
{
    try
    {
        // 首先检查软件是否启用
        var (_, _, isEnabled) = seccurity.ReadSecuritylist();
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
        var result = seccurity.blacklist(
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
var result = seccurity.Whitelist(userToCheck: 你的软件用户,machineToCheck: 机器码); 
```
调用实例：
```
private void btnWhitelistValidate_Click(object sender, EventArgs e)
{
    try
    {
        // 首先检查软件是否启用
        var (_, _, isEnabled) = seccurity.ReadSecuritylist();
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
        var result = seccurity.Whitelist(
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
var (users, machines, isEnabled) = seccurity.ReadSecuritylist();
```
调用实例：
```
private void LoadSecuritylist()
{
    try
    {
        var (users, machines, isEnabled) = seccurity.ReadSecuritylist();

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
 bool success = seccurity.GenerateSecuritylist(AllowedUsers: 用户数组,
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
    bool success = seccurity.GenerateSecuritylist(
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
### 生成机器码 返回 64字符串（256位哈希值）

采用 主板序列号 + CPU + 第一块硬盘序列号 + 主网卡MAC + 秘钥


调用方法
```
string MachineCode = seccurity.GenerateMachineCode("秘钥");
```
调用实例
```
static void Main(string[] args)
{
	string MachineCode = seccurity.GenerateMachineCode(secretKey);
	Console.WriteLine(MachineCode);
}

输出结果：D59DFDB186CC7D5C43CB9F331E2430C5047035BE7E459C812AD7834D3B9E9223
        BD5BE69FF4EC4170402E802E7F7B710F2BBCD559CC5BDE3B5596526970949D26
        FBCFA1DF3F305431429027FF2F63C9525A077F62DD242CD4D25B8103AD9ADB23
实验秘钥不同，机器码不同，保证绝对唯一性
```
根据公式计算：<img src="https://latex.codecogs.com/gif.image?\dpi{200}$P&space;\approx&space;1&space;-&space;e^{-k^2&space;/&space;(2N)}$" />

| 输入数量（k）      | 碰撞概率（P）    | 概率说明      |
|:-----------|:-----------:|-----------:|
| <img src="https://latex.codecogs.com/gif.image?\dpi{100}$k&space;=&space;10^6$" />      | <img src="https://latex.codecogs.com/gif.image?\dpi{100}$P&space;\approx&space;4.3&space;\times&space;10^{-66}$" />      | 100万台设备，碰撞概率几乎为0。      |
| <img src="https://latex.codecogs.com/gif.image?\dpi{100}$k&space;=&space;10^{12}$" />      | <img src="https://latex.codecogs.com/gif.image?\dpi{100}$P&space;\approx&space;4.3&space;\times&space;10^{-52}$" />      | 100亿台设备，碰撞概率几乎为0。      |
| <img src="https://latex.codecogs.com/gif.image?\dpi{100}$k&space;=&space;10^{18}$" />      | <img src="https://latex.codecogs.com/gif.image?\dpi{100}$P&space;\approx&space;4.3&space;\times&space;10^{-42}$" />      | 即使有百亿亿设备，碰撞概率仍可忽略不计。      |


