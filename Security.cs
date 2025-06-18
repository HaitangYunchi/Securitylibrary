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
using Microsoft.Win32;
using Newtonsoft.Json;
using System.Diagnostics;
using System.Management;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace SecurityLibrary
{
    /// <summary>
    /// 安全验证主类
    /// </summary>
    public class Security
    {
        private static readonly byte[] Salt = [0x48, 0x61, 0x69, 0x54, 0x61, 0x6E, 0x67, 0x59, 0x75, 0x6E, 0x63, 0x68, 0x69, 0x53, 0x61, 0x76];
        private readonly string _encryptionKey;

        /// <summary>
        /// 创建安全验证实例
        /// </summary>
        /// <param name="encryptionKey">加密密钥（长度至少32字符）</param>
        /// <exception cref="ArgumentException">密钥无效时抛出</exception>
        public Security(string encryptionKey)
        {
            if (string.IsNullOrWhiteSpace(encryptionKey))
                throw new ArgumentException("加密密钥不能为空", nameof(encryptionKey));

            if (encryptionKey.Length < 32)
                throw new ArgumentException("加密密钥长度至少需要32个字符", nameof(encryptionKey));

            _encryptionKey = encryptionKey;
        }

        /// <summary>
        /// 安全文件配置数据结构
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
            string json = CryptoHelper.Decrypt(encryptedJson, _encryptionKey);
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
        public (bool IsValid, string Message) Blacklist(string userToCheck = null, string machineToCheck = null, string filePath = "Seccurity.enc")
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
        /// <param name="allowedUsers">用户数组 AllowedUsers:数组变量</param>
        /// <param name="allowedMachines">机器码数组 AllowedMachines:数组变量</param>
        /// <param name="enableSoftware">是否启用</param>
        /// <param name="outputPath">安全文件路径，默认为"Seccurity.enc"</param>
        public bool GenerateSecuritylist(
            string[] allowedUsers,
            string[] allowedMachines,
            bool enableSoftware,
            string outputPath = "Seccurity.enc")
        {
            try
            {
                var settings = new SecuritylistSettings
                {
                    AllowedUsers = allowedUsers ?? Array.Empty<string>(),
                    AllowedMachines = allowedMachines ?? Array.Empty<string>(),
                    EnableSoftware = enableSoftware
                };

                settings.Checksum = ComputeSettingsChecksum(settings);

                File.WriteAllText(outputPath, CryptoHelper.Encrypt(JsonConvert.SerializeObject(settings), _encryptionKey));
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 生成机器码 主板 + cpu + mac + 硬盘（0）+ 秘钥
        /// </summary>
        ///  <param name="EncryptionKey">加密秘钥</param>
        /// <returns>256位十六进制哈希值 64 字符</returns>
        public string GenerateMachineCode(string EncryptionKey)
        {
            // 构建硬件信息组合
            var components = new StringBuilder();
            components.AppendLine($"Baseboard|{GetBaseboardSerial()}");
            components.AppendLine($"CPU|{GetCpuId()}");
            components.AppendLine($"MAC|{GetPrimaryMacAddress()}");
            components.AppendLine($"Drive|{GetSystemDriveSerial()}");
            components.AppendLine($"Key|{EncryptionKey}");

            // 生成不可逆哈希标识符
            return CryptoHelper.ComputeHash(components.ToString());
        }
        public static string GetBase64Fixed64CharString(string input)
        {
            // 将 EncryptionKey 字符串转换为字节数组
            byte[] keyBytes = Encoding.UTF8.GetBytes(input);

            // 创建等长的混淆数组
            byte[] obfuscatedSalt = new byte[keyBytes.Length];
            Buffer.BlockCopy(keyBytes, 0, obfuscatedSalt, 0, keyBytes.Length);

            // 使用原 ObfuscationKey（需确保此变量存在）
            for (int i = 0; i < obfuscatedSalt.Length; i++)
            {
                // 异或混淆
                obfuscatedSalt[i] ^= Salt[i % Salt.Length];
                // 循环位移 (左移5位等价操作)
                obfuscatedSalt[i] = (byte)((obfuscatedSalt[i] >> 3) | (obfuscatedSalt[i] << 5));
            }
            return Convert.ToBase64String(obfuscatedSalt);
        }
        #region 硬件信息获取

        // 获取主板序列号
        private string GetBaseboardSerial()
        {
            string uuidSerial = string.Empty;
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT UUID, IdentifyingNumber FROM Win32_ComputerSystemProduct");

                foreach (ManagementObject obj in searcher.Get())
                {
                    if (obj["UUID"] is string uuid && !string.IsNullOrWhiteSpace(uuid))
                    {
                        uuidSerial = uuid;
                    }
                    else
                    {
                        uuidSerial = "1F95C826-4086-6B4D-B5AA-9CAA942F6A4F";
                    }
                }
            }
            catch
            {
                uuidSerial = "UUID_1F95C826-4086-6B4D-B5AA-9CAA942F6A4F";
            }
            return uuidSerial;
        }

        // 获取CPU ID
        private string GetCpuId()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT ProcessorId FROM Win32_Processor");
                foreach (ManagementObject obj in searcher.Get())
                {
                    return obj["ProcessorId"]?.ToString() ?? "CPU_UNKNOWN";
                }
            }
            catch { }
            return "CPUID_BFEBFBFF00090672";
        }

        // 获取系统驱动器序列号
        private string GetSystemDriveSerial()
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    "SELECT SerialNumber FROM Win32_DiskDrive WHERE Index=0");
                foreach (ManagementObject obj in searcher.Get())
                {
                    return obj["SerialNumber"]?.ToString()?.Trim() ?? "DRIVE_UNKNOWN";
                }
            }
            catch { }
            return "DRIVE_WFN6Y72V";
        }

        // 获取主MAC地址
        private string GetPrimaryMacAddress()
        {
            try
            {
                NetworkInterface[] nics = NetworkInterface.GetAllNetworkInterfaces();
                var operationalNics = nics.Where(n =>
                    n.OperationalStatus == OperationalStatus.Up &&
                    !n.Description.Contains("Virtual") &&
                    !n.Description.Contains("Pseudo"));

                return operationalNics.FirstOrDefault()?.GetPhysicalAddress().ToString() ?? "MAC_UNKNOWN";
            }
            catch { }
            return "MAC_10FFE0688F04";
        }
        #endregion

        private bool ValidateChecksum(SecuritylistSettings settings)
        {
            return ComputeSettingsChecksum(settings) == settings.Checksum;
        }

        private string ComputeSettingsChecksum(SecuritylistSettings settings)
        {
            string data = string.Join(",", settings.AllowedUsers) +
                         string.Join(",", settings.AllowedMachines) +
                         settings.EnableSoftware.ToString() +
                         _encryptionKey;
            return CryptoHelper.ComputeHash(data);
        }
    }
}
