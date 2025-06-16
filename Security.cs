/*----------------------------------------------------------------
 * 版权所有 (c) 2025 HaiTangYunchi  保留所有权利
 * CLR版本：4.0.30319.42000
 * 公司名称：HaiTangYunchi
 * 命名空间：SecurityLibrary
 * 唯一标识：bfe44979-e3e4-4813-a9d7-6084112af553
 * 文件名：Security
 * 
 * 创建者：海棠云螭
 * 电子邮箱：haitangyunchi@126.com
 * 创建时间：2025/6/15 21:14:11
 * 版本：V1.0.0
 * 描述：
 *
 * ----------------------------------------------------------------
 * 修改人：
 * 时间：
 * 修改说明：
 *
 * 版本：V1.0.1
 *----------------------------------------------------------------*/

using Newtonsoft.Json;

namespace SecurityLibrary
{
    /// <summary>
    /// 黑名单验证器主类
    /// </summary>
    public class Security
    {
        /// <summary>
        /// 加密密钥(建议从配置读取)
        /// </summary>
        public static string EncryptionKey { get; set; } = "HaiTangYunchif&6ag2kFr%#*(&pjjR_gRH-yTutKg3LToV.7TIdOUoUNIkiLI_x";  //默认盐值，可以后期自定义获取该变量

        /// <summary>
        /// 黑名单配置数据结构
        /// </summary>
        public class SecuritylistSettings
        {
            public string[] DisabledUsers { get; set; } = [];
            public string[] DisabledMachines { get; set; } = [];
            public bool EnableSoftware { get; set; } = true;
            public string Checksum { get; set; } = string.Empty;
        }

        /// <summary>
        /// 读取安全文件内容
        /// </summary>
        /// <param name="filePath">安全文件路径(默认Seccurity.enc)</param>
        /// <returns>包含用户黑名单、机器黑名单和软件启用状态的元组</returns>
        public (string[] Users, string[] Machines, bool IsEnabled) ReadSecuritylist(string filePath = "Seccurity.enc")
        {
            if (!File.Exists(filePath))
                throw new FileNotFoundException("安全文件不存在", filePath);

            string encryptedJson = File.ReadAllText(filePath);
            string json = CryptoHelper.Decrypt(encryptedJson, EncryptionKey);
            SecuritylistSettings settings = JsonConvert.DeserializeObject<SecuritylistSettings>(json)
                ?? throw new InvalidDataException("安全文件格式错误");

            if (!ValidateChecksum(settings))
                throw new InvalidDataException("安全文件数据已被篡改");

            return (settings.DisabledUsers, settings.DisabledMachines, settings.EnableSoftware);
        }

        /// <summary>
        /// 验证指定用户和/或机器是否在安全文件中
        /// </summary>
        public (bool IsValid, string Message) Validate(string userToCheck = null, string machineToCheck = null, string filePath = "Seccurity.enc")
        {
            try
            {
                if (string.IsNullOrWhiteSpace(userToCheck) && string.IsNullOrWhiteSpace(machineToCheck))
                    return (false, "必须指定要检测的用户名或机器码");

                var (users, machines, isEnabled) = ReadSecuritylist(filePath);

                if (!isEnabled)
                    return (false, "软件已被管理员禁用");

                if (!string.IsNullOrWhiteSpace(userToCheck) && users.Contains(userToCheck, StringComparer.OrdinalIgnoreCase))
                    return (false, $"用户 '{userToCheck}' 被禁止使用");

                if (!string.IsNullOrWhiteSpace(machineToCheck) && machines.Contains(machineToCheck, StringComparer.OrdinalIgnoreCase))
                    return (false, $"机器码 '{machineToCheck}' 被禁止使用");

                return (true, "验证通过");
            }
            catch (Exception ex)
            {
                return (false, $"验证错误: {ex.Message}");
            }
        }

        /// <summary>
        /// 生成安全文件
        /// </summary>
        public bool GenerateSecuritylist(
            string[] disabledUsers,
            string[] disabledMachines,
            bool enableSoftware,
            string outputPath = "Seccurity.enc")
        {
            try
            {
                var settings = new SecuritylistSettings
                {
                    DisabledUsers = disabledUsers ?? Array.Empty<string>(),
                    DisabledMachines = disabledMachines ?? Array.Empty<string>(),
                    EnableSoftware = enableSoftware
                };

                settings.Checksum = ComputeSettingsChecksum(settings);

                File.WriteAllText(outputPath, CryptoHelper.Encrypt(JsonConvert.SerializeObject(settings), EncryptionKey));
                return true;
            }
            catch
            {
                return false;
            }
        }

        private bool ValidateChecksum(SecuritylistSettings settings)
        {
            return ComputeSettingsChecksum(settings) == settings.Checksum;
        }

        private string ComputeSettingsChecksum(SecuritylistSettings settings)
        {
            string data = string.Join(",", settings.DisabledUsers) +
                         string.Join(",", settings.DisabledMachines) +
                         settings.EnableSoftware.ToString();
            return CryptoHelper.ComputeHash(data);
        }
    }
}