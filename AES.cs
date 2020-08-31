using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ChatDemo
{
    public class AES
    {
        /// <summary>
        /// AES对称加密解密类
        /// </summary>
        public class AESHelper
        {
            #region 成员变量
            /// <summary>
            /// 密钥
            /// </summary>
            private static string _passwd = "ihlih*0037JOHT*)(PIJY*(()JI^)IO%";

            /// <summary>
            /// 密钥位数
            /// </summary>
            private const int _passwdLength = 32;

            /// <summary>
            /// 运算模式
            /// </summary>
            private static CipherMode _cipherMode = CipherMode.ECB;
            /// <summary>
            /// 填充模式
            /// </summary>
            private static PaddingMode _paddingMode = PaddingMode.PKCS7;
            /// <summary>
            /// 字符串采用的编码
            /// </summary>
            private static Encoding _encoding = Encoding.UTF8;
            #endregion

            #region 辅助方法
            /// <summary>
            /// 获取byte密钥数据
            /// </summary>
            /// <param name="password">密码</param>
            /// <returns></returns>
            private static byte[] GetKeyArray(string password)
            {
                if (password == null)
                {
                    password = string.Empty;
                }

                if (password.Length < _passwdLength)
                {
                    password = password.PadRight(_passwdLength, '0');
                }
                else if (password.Length > _passwdLength)
                {
                    password = password.Substring(0, _passwdLength);
                }

                return _encoding.GetBytes(password);
            }

            /// <summary>
            /// 将字符数组转换成字符串
            /// </summary>
            /// <param name="inputData"></param>
            /// <returns></returns>
            private static string ConvertByteToString(byte[] inputData)
            {
                StringBuilder sb = new StringBuilder(inputData.Length * 2);
                foreach (var b in inputData)
                {
                    sb.Append(b.ToString("X2"));
                }
                return sb.ToString();
            }

            /// <summary>
            /// 将字符串转换成字符数组
            /// </summary>
            /// <param name="inputString"></param>
            /// <returns></returns>
            private static byte[] ConvertStringToByte(string inputString)
            {
                if (inputString == null || inputString.Length < 2)
                {
                    throw new ArgumentException();
                }

                if ((inputString.Length % 2) != 0)
                {
                    inputString += " ";
                }

                int l = inputString.Length / 2;
                byte[] result = new byte[l];
                for (int i = 0; i < l; ++i)
                {
                    result[i] = Convert.ToByte(inputString.Substring(2 * i, 2), 16);
                }

                return result;
            }
            #endregion

            #region 加密
            /// <summary>
            /// 加密字节数据
            /// </summary>
            /// <param name="inputData">要加密的字节数据</param>
            /// <param name="password">密码</param>
            /// <returns></returns>
            public static byte[] Encrypt(byte[] inputData, string password)
            {
                using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
                {
                    aes.Key = GetKeyArray(password);
                    aes.Mode = _cipherMode;
                    aes.Padding = _paddingMode;
                    ICryptoTransform transform = aes.CreateEncryptor();
                    byte[] data = transform.TransformFinalBlock(inputData, 0, inputData.Length);
                    aes.Clear();
                    return data;
                }
            }

            /// <summary>
            /// 加密字符串(加密为16进制字符串)
            /// </summary>
            /// <param name="inputString">要加密的字符串</param>
            /// <param name="password">密码</param>
            /// <returns></returns>
            public static string Encrypt(string inputString, string password)
            {
                if (string.IsNullOrWhiteSpace(inputString) || string.IsNullOrWhiteSpace(password))
                {
                    return string.Empty;
                }

                byte[] toEncryptArray = _encoding.GetBytes(inputString);
                byte[] result = Encrypt(toEncryptArray, password);
                return ConvertByteToString(result);
            }

            /// <summary>
            /// 字符串加密(加密为16进制字符串)
            /// </summary>
            /// <param name="inputString">需要加密的字符串</param>
            /// <returns>加密后的字符串</returns>
            public static string EncryptString(string inputString)
            {
                if (string.IsNullOrWhiteSpace(_passwd))
                {
                    throw new ArgumentException("密钥不能为空");
                }
                return Encrypt(inputString, _passwd);
            }
            #endregion

            #region 解密
            /// <summary>
            /// 解密字节数组
            /// </summary>
            /// <param name="inputData">要解密的字节数据</param>
            /// <param name="password">密码</param>
            /// <returns></returns>
            public static byte[] Decrypt(byte[] inputData, string password)
            {
                using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
                {
                    aes.Key = GetKeyArray(password);
                    aes.Mode = _cipherMode;
                    aes.Padding = _paddingMode;
                    ICryptoTransform transform = aes.CreateDecryptor();
                    byte[] data = null;
                    try
                    {
                        data = transform.TransformFinalBlock(inputData, 0, inputData.Length);
                    }
                    catch
                    {
                        return null;
                    }
                    aes.Clear();
                    return data;
                }
            }

            /// <summary>
            /// 解密16进制的字符串为字符串
            /// </summary>
            /// <param name="inputString">要解密的字符串</param>
            /// <param name="password">密码</param>
            /// <returns>字符串</returns>
            public static string Decrypt(string inputString, string password)
            {
                if (string.IsNullOrWhiteSpace(inputString) || string.IsNullOrWhiteSpace(password))
                {
                    return string.Empty;
                }
                byte[] toDecryptArray = ConvertStringToByte(inputString);
                string decryptString = _encoding.GetString(Decrypt(toDecryptArray, password));
                return decryptString;
            }

            /// <summary>
            /// 解密16进制的字符串为字符串
            /// </summary>
            /// <param name="inputString">需要解密的字符串</param>
            /// <returns>解密后的字符串</returns>
            public static string DecryptString(string inputString)
            {
                if (string.IsNullOrWhiteSpace(_passwd))
                {
                    throw new ArgumentException("密钥不能为空");
                }
                return Decrypt(inputString, _passwd);
            }
            #endregion
        }
    }
}


