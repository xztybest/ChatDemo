using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace ChatDemo
{
    public class funcsum
    {
      
        //AES加密密钥随机生成时间密码
        public static string AESEnKeyGener()
        {
            string timepasswd = DateTime.Now.ToString("yyyyMMddHHmmss");
            return timepasswd;
        }
        //AES加密
        public static string AESEncry(string message,string passwd)
        {
            string ciphertext = AES.AESHelper.Encrypt(message, passwd);
            return ciphertext;
        }
        //AES解密
        public static string  AESDecry(string  message,string passwd)
        {
            string plaintext = AES.AESHelper.Decrypt(message,passwd);
            return plaintext;
        }
        //RSA加密
        public static string RSAEncry(string message)
        {
            string pubKeyFile = "\\CA\\root-cert.cer";//默认目录位置，公钥
            string publicKeyXml = RsaHelper.PublicKeyXmlFromCer(pubKeyFile, "");
            if (publicKeyXml == null)
            {
                
                return "0";
            }
            string rsaEncrypted = RsaHelper.Encrypt(message, publicKeyXml);

            if (rsaEncrypted == null)
                return "0";
            else
                return rsaEncrypted;
            return "1";

        }
        //RSA解密
        public static string RSADecry(string message)
        {
            string priKeyFile = "\\CA\\root.p12";//默认目录位置，私钥
            string privateKyeXml= RsaHelper.PrivateKeyXmlFromPKCS12(priKeyFile, "");
            if (privateKyeXml == null)
            {
                return "0";
            }

            string rsaDecrypted = RsaHelper.Decrypt(message, privateKyeXml);

            if (rsaDecrypted == null)
                return "0";
            else
                return rsaDecrypted;
            return "1";


        }
        //RSA签名
        public static string messagesign(string message)
        {
            string priKeyFile = "\\CA\\root.p12";//默认目录位置，私钥
            string privateKyeXml = RsaHelper.PrivateKeyXmlFromPKCS12(priKeyFile, "");
            if (privateKyeXml == null)
            {
                return "0";
            }
            string signvalue = RsaHelper.SenderHashAndSign(message, privateKyeXml);
            if (signvalue == null)
            {
                return "0";
            }
            else
            {
                return signvalue;
            }

        }
        //RSA验证签名
        public static string messagesigncheck(string messagesign, string signvalue)
        {
            string pubKeyFile = "\\CA\\root-cert.cer";//默认目录位置，公钥
            string publicKeyXml = RsaHelper.PublicKeyXmlFromCer(pubKeyFile, "");
            if (publicKeyXml == null)
            {

                return "0";
            }
            bool checkresult = RsaHelper.ReceiverVerifyHash(messagesign, signvalue, publicKeyXml);
            if (checkresult)
            {
                return "1";
            }
            else
            {
                return "0";
            }
        }

        //用户添加
        public static string useraddmysql(string username,string passwd)
        {
            return "1";
        }
        //用户登录验证
        public static string userlogincheck(string username,string passwd)
        {
            return "1";
        }

    }
}
