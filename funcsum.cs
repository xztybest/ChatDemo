using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using MySql.Data.MySqlClient;

namespace ChatDemo
{
    public class funcsum
    {
        public static string connString = "server=localhost;port=3306;user=root;password=root;database=xxq;";//根据自己的实际数据库进行设置
        public static MySqlConnection conn = new MySqlConnection(connString);
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
        public static string useraddmysql(string usernamei, string passwdi)
        {
            conn.Open();
            string checksql = "select * from username where username='" + usernamei+"'";
            MySqlCommand CMDC = new MySqlCommand(checksql, conn);
            MySqlDataReader Readata = CMDC.ExecuteReader();
            if(Readata.Read())
            {
                conn.Close();
                return "2";
            }
            else
            {
                Readata.Close();
                //MySqlConnection conn2 = new MySqlConnection(connString);
                string sqluseradd = "insert into username(username,userpasswd) values('" + usernamei + "'," + "'" + passwdi + "' );";
                MySqlCommand CMD1 = new MySqlCommand(sqluseradd, conn);
                int back = CMD1.ExecuteNonQuery();
                if (back > 0)
                {
                    conn.Close();
                    return "1";
                }
                else
                {
                    conn.Close();
                    return "0";
                }

            }
            
        }
        //用户登录验证
        public static string userlogincheck(string username,string passwd)
        {
            conn.Open();
            string checksql = "select * from username where username='" + username + "' and userpasswd='" + passwd + "'";
            MySqlCommand CMDC = new MySqlCommand(checksql, conn);
            MySqlDataReader Readata = CMDC.ExecuteReader();
            if (Readata.Read())
            {
                conn.Close();
                return "1";
            }
            else
            {
                conn.Close();
                return "0";
            }

            
        }

        //向客户端发送信息
        public static string sendmessagetoclient(string message)
        {

            return "1";
        }
    }
}
