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
            public string[] AllowedUsers { get; set; } = [];
            public string[] AllowedMachines { get; set; } = [];
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

            return (settings.AllowedUsers, settings.AllowedMachines, settings.EnableSoftware);
        }

        /// <summary>
        /// 验证黑名单用户和/或机器是否在安全文件中
        /// 如果用户或机器在黑名单中，则拒绝访问
        /// </summary>
        /// <param name="userToCheck">要验证的用户名</param>
        /// <param name="machineToCheck">要验证的机器码</param>
        /// <param name="filePath">安全文件路径，默认为"Seccurity.enc"</param>
        /// <returns>
        /// 返回元组 (IsValid, Message):
        /// - IsValid: 验证是否通过
        /// - Message: 验证结果消息
        /// </returns>
        public (bool IsValid, string Message) blacklist(string userToCheck = null, string machineToCheck = null, string filePath = "Seccurity.enc")
        {
            try
            {
                if (string.IsNullOrWhiteSpace(userToCheck) && string.IsNullOrWhiteSpace(machineToCheck))
                    return (false, "必须指定要检测的用户名或机器码");

                var (users, machines, isEnabled) = ReadSecuritylist(filePath);

                if (!isEnabled)
                    return (false, "软件已被管理员禁用");

                bool userBlacklisted = !string.IsNullOrWhiteSpace(userToCheck) &&
                                     users.Contains(userToCheck, StringComparer.OrdinalIgnoreCase);
                bool machineBlacklisted = !string.IsNullOrWhiteSpace(machineToCheck) &&
                                         machines.Contains(machineToCheck, StringComparer.OrdinalIgnoreCase);

                // 两个都验证的情况
                if (!string.IsNullOrWhiteSpace(userToCheck) && !string.IsNullOrWhiteSpace(machineToCheck))
                {
                    if (userBlacklisted && machineBlacklisted)
                        return (false, $"用户 '{userToCheck}' 和机器码 '{machineToCheck}' 均被禁止使用");
                    if (userBlacklisted)
                        return (false, $"用户 '{userToCheck}' 被禁止使用");
                    if (machineBlacklisted)
                        return (false, $"机器码 '{machineToCheck}' 被禁止使用");
                }
                // 只验证用户名的情况
                else if (!string.IsNullOrWhiteSpace(userToCheck))
                {
                    if (userBlacklisted)
                        return (false, $"用户 '{userToCheck}' 被禁止使用");
                }
                // 只验证机器码的情况
                else
                {
                    if (machineBlacklisted)
                        return (false, $"机器码 '{machineToCheck}' 被禁止使用");
                }

                return (true, "验证通过");
            }
            catch (Exception ex)
            {
                return (false, $"验证错误: {ex.Message}");
            }
        }

        /// <summary>
        /// 验证白名单用户和/或机器是否在安全文件中
        /// 只有用户或机器在白名单中，才允许访问
        /// </summary>
        /// <param name="userToCheck">要验证的用户名</param>
        /// <param name="machineToCheck">要验证的机器码</param>
        /// <param name="filePath">安全文件路径，默认为"Seccurity.enc"</param>
        /// <returns>
        /// 返回元组 (IsValid, Message):
        /// - IsValid: 验证是否通过
        /// - Message: 验证结果消息
        /// </returns>
        public (bool IsValid, string Message) Whitelist(string userToCheck = null, string machineToCheck = null, string filePath = "Seccurity.enc")
        {
            try
            {
                if (string.IsNullOrWhiteSpace(userToCheck) && string.IsNullOrWhiteSpace(machineToCheck))
                    return (false, "必须指定要验证的用户名或机器码");

                var (users, machines, isEnabled) = ReadSecuritylist(filePath);

                if (!isEnabled)
                    return (false, "软件已被管理员禁用");

                bool userWhitelisted = string.IsNullOrWhiteSpace(userToCheck) ||
                                     users.Contains(userToCheck, StringComparer.OrdinalIgnoreCase);
                bool machineWhitelisted = string.IsNullOrWhiteSpace(machineToCheck) ||
                                         machines.Contains(machineToCheck, StringComparer.OrdinalIgnoreCase);

                // 两个都验证的情况
                if (!string.IsNullOrWhiteSpace(userToCheck) && !string.IsNullOrWhiteSpace(machineToCheck))
                {
                    if (!userWhitelisted && !machineWhitelisted)
                        return (false, $"用户 '{userToCheck}' 和机器码 '{machineToCheck}' 均未授权");
                    if (!userWhitelisted)
                        return (false, $"用户 '{userToCheck}' 未授权");
                    if (!machineWhitelisted)
                        return (false, $"机器码 '{machineToCheck}' 未授权");
                }
                // 只验证用户名的情况
                else if (!string.IsNullOrWhiteSpace(userToCheck))
                {
                    if (!userWhitelisted)
                        return (false, $"用户 '{userToCheck}' 未授权");
                }
                // 只验证机器码的情况
                else
                {
                    if (!machineWhitelisted)
                        return (false, $"机器码 '{machineToCheck}' 未授权");
                }

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
        /// <param name="AllowedUsers:数组变量">用户名变量数组</param>
        /// <param name="AllowedMachines:数组变量">机器码数组</param>
        /// <param name="enableSoftware:true or false">是否启用</param>
        /// <param name="outputPath">安全文件路径，默认为"Seccurity.enc"</param>
        /// <returns>
        public bool GenerateSecuritylist(
            string[] AllowedUsers,
            string[] AllowedMachines,
            bool enableSoftware,
            string outputPath = "Seccurity.enc")
        {
            try
            {
                var settings = new SecuritylistSettings
                {
                    AllowedUsers = AllowedUsers ?? Array.Empty<string>(),
                    AllowedMachines = AllowedMachines ?? Array.Empty<string>(),
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
            string data = string.Join(",", settings.AllowedUsers) +
                         string.Join(",", settings.AllowedMachines) +
                         settings.EnableSoftware.ToString();
            return CryptoHelper.ComputeHash(data);
        }
    }
}