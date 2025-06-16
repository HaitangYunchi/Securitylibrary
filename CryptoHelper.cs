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

using System.Text;
using System.Security.Cryptography;
namespace SecurityLibrary
{
    /// <summary>
    /// 加密解密辅助类
    /// </summary>
    public static class CryptoHelper
    {
        private static readonly byte[] Salt = [0x48, 0x61, 0x69, 0x54, 0x61, 0x6E, 0x67, 0x59, 0x75, 0x6E, 0x63, 0x68, 0x69, 0x53, 0x61, 0x76];
        private const int Iterations = 1000;

        /// <summary>
        /// 加密字符串
        /// </summary>
        public static string Encrypt(string plainText, string passPhrase)
        {
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);

            using Aes aes = Aes.Create();
            byte[] keyMaterial = Rfc2898DeriveBytes.Pbkdf2(
                password: Encoding.UTF8.GetBytes(passPhrase),
                salt: Salt,
                iterations: Iterations,
                hashAlgorithm: HashAlgorithmName.SHA256,
                outputLength: 48); // 32字节密钥 + 16字节IV = 48字节

            aes.Key = keyMaterial.AsSpan(0, 32).ToArray();
            aes.IV = keyMaterial.AsSpan(32, 16).ToArray();

            using MemoryStream ms = new();
            using (CryptoStream cs = new(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
            {
                cs.Write(plainBytes, 0, plainBytes.Length);
            }
            return Convert.ToBase64String(ms.ToArray());
        }

        /// <summary>
        /// 解密字符串
        /// </summary>
        public static string Decrypt(string cipherText, string passPhrase)
        {
            byte[] cipherBytes = Convert.FromBase64String(cipherText);

            using Aes aes = Aes.Create();
            byte[] keyMaterial = Rfc2898DeriveBytes.Pbkdf2(
                password: Encoding.UTF8.GetBytes(passPhrase),
                salt: Salt,
                iterations: Iterations,
                hashAlgorithm: HashAlgorithmName.SHA256,
                outputLength: 48); // 32字节密钥 + 16字节IV = 48字节

            aes.Key = keyMaterial.AsSpan(0, 32).ToArray();
            aes.IV = keyMaterial.AsSpan(32, 16).ToArray();

            using MemoryStream ms = new();
            using (CryptoStream cs = new(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
            {
                cs.Write(cipherBytes, 0, cipherBytes.Length);
            }
            return Encoding.UTF8.GetString(ms.ToArray());
        }

        /// <summary>
        /// 计算SHA256哈希
        /// </summary>
        public static string ComputeHash(string input)
        {
            using SHA256 sha256 = SHA256.Create();
            byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
            return BitConverter.ToString(bytes).Replace("-", "").ToLower();
        }
    }
}
