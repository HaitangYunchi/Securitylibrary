# SecurityLibrary.dll ʹ���ֲ�

���ȳ������� SecurityLibrary.dll ���ڳ����� using SecurityLibrary;
���ʹ���б�����ʹ����ͬ�ķ�ʽ���� Newtonsoft.Json.dll
��ȫ�ļ���λ�̶����ƣ�Seccurity.enc

ʵ������
Security validator = new();

���÷�����
Security.EncryptionKey = "���ȡ���ļ�����ֵ";	//	���ü�����ֵ

//��֤ ���ز���ֵ �û��ͻ�����������д��һ���ɣ����߶���дҲ�У�������Զ�ʶ������һ��
var result = validator.Validate(userToCheck: �������û�,machineToCheck: ������); 

����ʵ����
private void btnValidate_Click(object sender, EventArgs e)
{
    // ������֤
    if (string.IsNullOrWhiteSpace(txtUser.Text) && string.IsNullOrWhiteSpace(txtMachine.Text))
    {
        MessageBox.Show("��������֤��Ϣ", "��ʾ",MessageBoxButtons.OK, MessageBoxIcon.Warning);
        return;
    }

    var result = validator.Validate(
        userToCheck: txtUser.Text,
        machineToCheck: txtMachine.Text);           
    // �����֤ʧ�ܣ��˳�����
    if (!result.IsValid)
    {
        MessageBox.Show(result.Message, result.IsValid ? "��֤ͨ��" : "��֤ʧ��", MessageBoxButtons.OK, result.IsValid ? MessageBoxIcon.Information : MessageBoxIcon.Error);
        MessageBox.Show("�˴�����֤��ͨ�����߹���Ա����������ʱ�ſ����ĺ�������\n��֤����������������ʱ����", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        return;
        Application.Exit();   // �����ֹ���Զ��˳����,��ע�͵������return
    }
    MessageBox.Show("�˴�����֤ͨ����ĺ���ִ�д��룬��֤����������������ʱ���ء�", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Information);
}

//��ȡ��ȫ�ļ��б� ��������
var (users, machines, isEnabled) = validator.ReadSecuritylist();

����ʵ����
private void LoadSecuritylist()
{
    try
    {
        var (users, machines, isEnabled) = validator.ReadSecuritylist();

        // ����ȡ��������ʾ����Ӧ�ı���
        txtUsers.Text = string.Join(Environment.NewLine, users);
        txtMachines.Text = string.Join(Environment.NewLine, machines);
        chkEnabled.Checked = isEnabled;

        statusLabel.Text = "��ȫ�ļ����سɹ�";
    }
    catch (Exception ex)
    {
        // �ļ�������ʱ��ʾ�����ݣ�����������ʾ��ʾ
        if (!(ex is System.IO.FileNotFoundException))
        {
            MessageBox.Show($"���ذ�ȫ�ļ�ʧ��: {ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        statusLabel.Text = "δ���ְ�ȫ�ļ���";
    }
}

// ���ɰ�ȫ�ļ�
 bool success = validator.GenerateSecuritylist(disabledUsers: �û�����,disabledMachines: ����������,enableSoftware: �Ƿ�����);

 ����ʵ����
 private void btnGenerate_Click(object sender, EventArgs e)
{
    // �����û����� - ���зָȥ���հ���
    var users = txtUsers.Text.Split(new[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries)
        .Select(u => u.Trim())
        .Where(u => !string.IsNullOrEmpty(u))
        .ToArray();

    var machines = txtMachines.Text.Split(new[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries)
        .Select(m => m.Trim())
        .Where(m => !string.IsNullOrEmpty(m))
        .ToArray();

    // ����DLL���ɰ�ȫ�ļ�
    bool success = validator.GenerateSecuritylist(
        disabledUsers: users,
        disabledMachines: machines,
        enableSoftware: chkEnabled.Checked);

    // ��ʾ�������
    if (success)
    {
        statusLabel.Text = "��ȫ�ļ����ɳɹ�";
        MessageBox.Show($"��ȫ�ļ����ɳɹ�!{Environment.NewLine}�ļ��ѱ���ΪSeccurity.enc",
            "�ɹ�", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }
    else
    {
        statusLabel.Text = "��ȫ�ļ�����ʧ��";
        MessageBox.Show("��ȫ�ļ�����ʧ��",
            "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
    }
}
