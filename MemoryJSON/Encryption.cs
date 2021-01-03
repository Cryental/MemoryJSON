using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;

namespace MemoryJSON
{
    // Based On: https://gist.github.com/doncadavona/fd493b6ced456371da8879c22bb1c263

    internal static class Encryption
    {
        private static readonly Encoding Encoding = Encoding.UTF8;

        internal static byte[] Encrypt(string plainText, string key)
        {
            try
            {
                var aes = new RijndaelManaged
                {
                    KeySize = 256,
                    BlockSize = 128,
                    Padding = PaddingMode.PKCS7,
                    Mode = CipherMode.CBC,
                    Key = Encoding.GetBytes(key)
                };

                aes.GenerateIV();

                var aesEncrypt = aes.CreateEncryptor(aes.Key, aes.IV);
                var buffer = Encoding.GetBytes(plainText);

                var encryptedText = Convert.ToBase64String(aesEncrypt.TransformFinalBlock(buffer, 0, buffer.Length));

                var mac = "";

                mac = BitConverter.ToString(HmacSha256(Convert.ToBase64String(aes.IV) + encryptedText, key))
                    .Replace("-", "").ToLower();

                var keyValues = new Dictionary<string, object>
                {
                    {"iv", Convert.ToBase64String(aes.IV)},
                    {"value", encryptedText},
                    {"mac", mac}
                };

                var serializer = new JavaScriptSerializer();

                return Encoding.GetBytes(serializer.Serialize(keyValues));
            }
            catch
            {
                throw new Exception("There was a problem while encrypting the file.");
            }
        }

        internal static string Decrypt(byte[] byteText, string key)
        {
            try
            {
                var aes = new RijndaelManaged
                {
                    KeySize = 256,
                    BlockSize = 128,
                    Padding = PaddingMode.PKCS7,
                    Mode = CipherMode.CBC,
                    Key = Encoding.GetBytes(key)
                };

                var base64DecodedStr = Encoding.GetString(byteText);

                var ser = new JavaScriptSerializer();
                var payload = ser.Deserialize<Dictionary<string, string>>(base64DecodedStr);

                aes.IV = Convert.FromBase64String(payload["iv"]);

                var aesDecrypt = aes.CreateDecryptor(aes.Key, aes.IV);
                var buffer = Convert.FromBase64String(payload["value"]);

                return Encoding.GetString(aesDecrypt.TransformFinalBlock(buffer, 0, buffer.Length));
            }
            catch
            {
                throw new Exception("There was a problem while decrypting the file.");
            }
        }

        private static byte[] HmacSha256(string data, string key)
        {
            using (var hmac = new HMACSHA256(Encoding.GetBytes(key)))
            {
                return hmac.ComputeHash(Encoding.GetBytes(data));
            }
        }
    }
}