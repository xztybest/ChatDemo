using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ChatDemo
{
    public class RsaHelper
    {
        /*
        * 1. 创建根证书私钥
             openssl genrsa -out root-key.key 1024
        * 2. 创建根证书请求文件
              openssl req -new -out root-req.csr -key root-key.key -keyform PEM
        * 3. 自签根证书
              openssl x509 -req -extfile d:\test\openssl.cnf -extensions v3_req  -in root-req.csr -out root-cert.cer -signkey root-key.key -CAcreateserial -days 3650 
        * 4. 导出p12（pfx）格式证书（包含公、私钥） （p12：PKCS#12，PFX: Personal Information Exchange）
              openssl pkcs12 -export -clcerts -in root-cert.cer -inkey root-key.key -out root.p12
        * 5. 从.p12文件中提取私钥
             X509Certificate2 x509 = new X509Certificate2(p12-file, password, X509KeyStorageFlags.Exportable);
             var publicKey = x509.PublicKey.Key.ToXmlString(false);
             var privateKey = x509.PrivateKey.ToXmlString(true);
       *  6. RSA参数：Modulus、Exponent、P、Q、DP、DQ、InverseQ、D
                p, q [P = p, Q = q]
                n=p*q [Modulus = n]
                φ(n)=(p-1)*(q-1) 
                ed = 1 mod φ(n) [Exponent = e, D = d][e称为指数，用作公钥；d是e模φ(n)的逆元，用作私钥][加密：c = m ^ e mod n，解密：c ^ d mod n]
                DP=d mod p-1 
                DQ=d mod q-1 
                q* InverseQ=1 mod p [InverseQ是q模p的逆元]

       RSA公钥：
       <RSAKeyValue>
           <Modulus>
               q/Yb0j6iQiF1Pu0b1+7/13Fz9iMaepwXmEXQScZbuVdf9VBQ50j5+gj5a+E7FuxQxHcSv86Hn2TCZY/pBOHlNwh/736zhMoqfacfjEtRbplKG2q9WvywUnQsrGzkFnL3OmG5YpvW2EmXh2cOFNtGroibSfWkWI9sNjCo++/gmJE=
           </Modulus>
           <Exponent>
               AQAB
           </Exponent>
       </RSAKeyValue>"

       RSA私钥：
       <RSAKeyValue>
           <Modulus>
               q/Yb0j6iQiF1Pu0b1+7/13Fz9iMaepwXmEXQScZbuVdf9VBQ50j5+gj5a+E7FuxQxHcSv86Hn2TCZY/pBOHlNwh/736zhMoqfacfjEtRbplKG2q9WvywUnQsrGzkFnL3OmG5YpvW2EmXh2cOFNtGroibSfWkWI9sNjCo++/gmJE=
           </Modulus>
           <Exponent>
               AQAB
           </Exponent>
           <P>
               2bO1ztOmt1hn3Nl0O8Z8+F7KAe+xp5wJXBPuKs5wUypoGO52JGqW5U1003VsEQjXaJdGX3NJBK9Bb5ZD4zucWw==
           </P>
           <Q>
               yjZzxrDH45vhz77LwCcg+GbnV59WFewD8woQ8wGerS+2IpksBoSbtvsB2qhA7QAbIgroAkd9q5lK1bKeQaqigw==
           </Q> 
           <DP>
               C3eH0Akd8vJZJizeDnf6BSsZANkbRnTVmWADX4XYLMlDCm0lE+35XMKjsK+yrYMFtaCiOEzeP7zreXE0yjdNmQ==
           </DP>
           <DQ>
               rS2rQ8vctQqofqHZn6wjKXn/wOQd9tJVo4zIbUXC3nGRG9pwgPiK30/jC5+zUwYXNrV+c41EjHTRSWka7gQz/w==
           </DQ>
           <InverseQ>
               QiprMadsDyt3w6CnO9xoJKaxH7xGsJkbLcqtlleJP4SfNB2XqRcT49ryoPGdVUWqbeGprxtkTqezPTXMJyIDQQ==
           </InverseQ>
           <D>
               b4cyKhzXTb63dTWBLn5izk9V31iLDuR35Rm6am7NBJsnsEoD/s1023bAlfhBQ6/G/nUf4ujHS1ilQAujHLiJ2SRAg1imYmQCapnc8GA5I5Z4MvarrfAzZQ0QxNSZ7+6k+SHIeMCBbRHHStg3i5WROYER9JHtFd+8GLOA45mi31U=
           </D>
       </RSAKeyValue>


       */

        public static void Example()
        {
            //string original0 = "The quick brown fox jumps over a lazy dog.";
            string original0 = "我是一片云，天空是我家，朝迎旭日升，暮送夕阳下。";

            //xml格式、Base64编码、大端（低地址存放高数位，高地址存放低数位）
            //string xmlPublicKey = "<RSAKeyValue><Modulus>q/Yb0j6iQiF1Pu0b1+7/13Fz9iMaepwXmEXQScZbuVdf9VBQ50j5+gj5a+E7FuxQxHcSv86Hn2TCZY/pBOHlNwh/736zhMoqfacfjEtRbplKG2q9WvywUnQsrGzkFnL3OmG5YpvW2EmXh2cOFNtGroibSfWkWI9sNjCo++/gmJE=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";
            //string xmlPrivateKey = "<RSAKeyValue><Modulus>q/Yb0j6iQiF1Pu0b1+7/13Fz9iMaepwXmEXQScZbuVdf9VBQ50j5+gj5a+E7FuxQxHcSv86Hn2TCZY/pBOHlNwh/736zhMoqfacfjEtRbplKG2q9WvywUnQsrGzkFnL3OmG5YpvW2EmXh2cOFNtGroibSfWkWI9sNjCo++/gmJE=</Modulus> <Exponent>AQAB</Exponent> <P>2bO1ztOmt1hn3Nl0O8Z8+F7KAe+xp5wJXBPuKs5wUypoGO52JGqW5U1003VsEQjXaJdGX3NJBK9Bb5ZD4zucWw==</P> <Q>yjZzxrDH45vhz77LwCcg+GbnV59WFewD8woQ8wGerS+2IpksBoSbtvsB2qhA7QAbIgroAkd9q5lK1bKeQaqigw==</Q> <DP>C3eH0Akd8vJZJizeDnf6BSsZANkbRnTVmWADX4XYLMlDCm0lE+35XMKjsK+yrYMFtaCiOEzeP7zreXE0yjdNmQ==</DP> <DQ>rS2rQ8vctQqofqHZn6wjKXn/wOQd9tJVo4zIbUXC3nGRG9pwgPiK30/jC5+zUwYXNrV+c41EjHTRSWka7gQz/w==</DQ> <InverseQ>QiprMadsDyt3w6CnO9xoJKaxH7xGsJkbLcqtlleJP4SfNB2XqRcT49ryoPGdVUWqbeGprxtkTqezPTXMJyIDQQ==</InverseQ> <D>b4cyKhzXTb63dTWBLn5izk9V31iLDuR35Rm6am7NBJsnsEoD/s1023bAlfhBQ6/G/nUf4ujHS1ilQAujHLiJ2SRAg1imYmQCapnc8GA5I5Z4MvarrfAzZQ0QxNSZ7+6k+SHIeMCBbRHHStg3i5WROYER9JHtFd+8GLOA45mi31U=</D> </RSAKeyValue>";

            string xmlPublicKey = PublicKeyXmlFromCer("H:\\CA\\root-cert.cer", "");
            string xmlPrivateKey = PrivateKeyXmlFromPKCS12("H:\\CA\\root.p12", "");

            string encrypted = RsaHelper.Encrypt(original0, xmlPublicKey);
            string decrypted = RsaHelper.Decrypt(encrypted, xmlPrivateKey);

            string signature = RsaHelper.SenderHashAndSign(original0, xmlPrivateKey);
            bool verifySig = RsaHelper.ReceiverVerifyHash(original0, signature, xmlPublicKey);
        }

        /// <summary>
        /// 对文本进行签名
        /// </summary>
        /// <param name="strToSign">被签名的文本</param>
        /// <param name="senderPrivateKeyXml">签名者的私钥（XML格式）</param>
        /// <returns>文本Hash值的签名/null</returns>
        public static string SenderHashAndSign(string strToSign, string senderPrivateKeyXml)
        {
            if (string.IsNullOrEmpty(strToSign) || string.IsNullOrEmpty(senderPrivateKeyXml))
                return null;

            string signature = null;

            using (RSACryptoServiceProvider myRsa = new RSACryptoServiceProvider())
            {
                SHA1Managed hash = new SHA1Managed();
                byte[] dataToSign = Encoding.UTF8.GetBytes(strToSign);
                byte[] hashedData;

                myRsa.FromXmlString(senderPrivateKeyXml);
                hashedData = hash.ComputeHash(dataToSign);

                var tmp = myRsa.SignHash(hashedData, CryptoConfig.MapNameToOID("SHA1"));
                signature = Convert.ToBase64String(tmp);
            }

            return signature;
        }

        /// <summary>
        /// 对签名进行验证
        /// </summary>
        /// <param name="signedData">被签名的文本</param>
        /// <param name="signature">签名（发送方给出的签名值）</param>
        /// <param name="senderPublicKeyXml">签名者的公钥</param>
        /// <returns>true/false</returns>
        public static bool ReceiverVerifyHash(string signedData, string signature, string senderPublicKeyXml)
        {
            if (string.IsNullOrEmpty(signedData) || string.IsNullOrEmpty(signature) || string.IsNullOrEmpty(senderPublicKeyXml))
                return false;

            bool verified = false;

            using (RSACryptoServiceProvider myRsa = new RSACryptoServiceProvider())
            {
                SHA1Managed hash = new SHA1Managed();
                byte[] hashedData;
                byte[] signedData2 = Encoding.UTF8.GetBytes(signedData);
                byte[] signature2 = Convert.FromBase64String(signature);

                myRsa.FromXmlString(senderPublicKeyXml);
                bool dataOK = myRsa.VerifyData(signedData2, CryptoConfig.MapNameToOID("SHA1"), signature2);

                if (!dataOK)
                    return false;

                hashedData = hash.ComputeHash(signedData2);
                verified = myRsa.VerifyHash(hashedData, CryptoConfig.MapNameToOID("SHA1"), signature2);
            }

            return verified;
        }

        /// <summary>
        /// 从PKCS#12证书文件（.p12, .pfx）中导出私钥
        /// </summary>
        /// <param name="filePath">文件全路径</param>
        /// <param name="password">保护文件的密码（若没有密码，则为""）</param>
        /// <returns>XML格式私钥/null</returns>
        public static string PrivateKeyXmlFromPKCS12(string filePath, string password)
        {
            string xmlPrivateKey = null;

            using (X509Certificate2 x509 = new X509Certificate2(filePath, password, X509KeyStorageFlags.Exportable))
            {
                xmlPrivateKey = x509.PrivateKey.ToXmlString(true);
            }

            return xmlPrivateKey;
        }

        /// <summary>
        /// 从CER证书文件中导出公钥
        /// </summary>
        /// <param name="filePath">文件全路径</param>
        /// <param name="password">保护文件的密码（若没有密码，则为""</param>
        /// <returns>XML格式公钥/null</returns>
        public static string PublicKeyXmlFromCer(string filePath, string password)
        {
            string xmlPublicKey = null;

            using (X509Certificate2 x509 = new X509Certificate2(filePath, password, X509KeyStorageFlags.Exportable))
            {
                xmlPublicKey = x509.PublicKey.Key.ToXmlString(false);
            }

            return xmlPublicKey;
        }

        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="text">待加密的文本</param>
        /// <param name="publicKeyXml">公钥（XML格式）</param>
        /// <returns>加密后的Base64编码/null</returns>
        public static string Encrypt(string text, string publicKeyXml)
        {
            if (string.IsNullOrEmpty(text) || string.IsNullOrEmpty(publicKeyXml))
                return null;

            string encrypted = null;

            using (RSACryptoServiceProvider myRsa = new RSACryptoServiceProvider())
            {
                //导入公钥.
                myRsa.FromXmlString(publicKeyXml);

                var tmp = Encoding.UTF8.GetBytes(text);
                var enc = myRsa.Encrypt(tmp, false);

                encrypted = Convert.ToBase64String(enc);
            }

            return encrypted;
        }

        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="cipherText">加密信息（Base64编码）</param>
        /// <param name="privateKeyXml">私钥（XML格式）</param>
        /// <returns>解密后的文本/null</returns>
        public static string Decrypt(string cipherText, string privateKeyXml)
        {
            if (string.IsNullOrEmpty(cipherText) || string.IsNullOrEmpty(privateKeyXml))
                return null;

            string decrypted = null;

            using (RSACryptoServiceProvider myRsa = new RSACryptoServiceProvider())
            {
                //导入私钥.
                myRsa.FromXmlString(privateKeyXml);

                var tmp = System.Convert.FromBase64String(cipherText);
                var dec = myRsa.Decrypt(tmp, false);

                decrypted = Encoding.UTF8.GetString(dec);
            }

            return decrypted;
        }

        internal static string Encrypt(object original0, string publicKeyXml)
        {
            throw new NotImplementedException();
        }
    }
}
