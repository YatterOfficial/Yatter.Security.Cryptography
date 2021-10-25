using System;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Serialization;

namespace Yatter.Security.Cryptography
{
    public class CryptographyKeyManager
    {
        private RSACryptoServiceProvider rsaCryptoServiceProvider = new RSACryptoServiceProvider();

        private RSAParameters _publicKey;
        private RSAParameters _privateKey;

        public CryptographyKeyManager() { }

        public string RSAEncryptBase64(string text)
        {
            var data = Encoding.Unicode.GetBytes(text);
            var cypher = rsaCryptoServiceProvider.Encrypt(data, false);

            return Convert.ToBase64String(cypher);
        }

        public string RSAEncrypt(string text)
        {
            var data = Encoding.Unicode.GetBytes(text);
            var cypher = rsaCryptoServiceProvider.Encrypt(data, false);

            if(cypher==null)
            {
                return string.Empty;
            }
            else
            {
#pragma warning disable CS8603 // Possible null reference return.
                return Convert.ToString(cypher);
#pragma warning restore CS8603 // Possible null reference return.
            }
        }

        public string DecryptBase64(string base64Cypher)
        {
            var encodedBytes = Convert.FromBase64String(base64Cypher);

            var decodedBytes = rsaCryptoServiceProvider.Decrypt(encodedBytes, false);

            return Encoding.Unicode.GetString(decodedBytes);
        }

        public int ImportRSAPublicKey(ReadOnlySpan<byte> source)
        {
            int bytesRead;
            rsaCryptoServiceProvider.ImportRSAPublicKey(source, out bytesRead);

            return bytesRead;
        }

        public int ImportRSAPrivateKey(ReadOnlySpan<byte> source)
        {
            int bytesRead;
            rsaCryptoServiceProvider.ImportRSAPrivateKey(source, out bytesRead);

            return bytesRead;
        }

        public byte[] ExportRSAPrivateKey()
        {
            return rsaCryptoServiceProvider.ExportRSAPrivateKey();
        }

        public byte[] ExportRSAPublicKey()
        {
            return rsaCryptoServiceProvider.ExportRSAPublicKey();
        }

        public string ExportPrivateKey()
        {
            var sw = new StringWriter();
            var xs = new XmlSerializer(typeof(RSAParameters));
            xs.Serialize(sw, _privateKey);
            return sw.ToString();
        }

        public string ExportPublicKey()
        {
            var sw = new StringWriter();
            var xs = new XmlSerializer(typeof(RSAParameters));
            xs.Serialize(sw, _publicKey);
            return sw.ToString();
        }

        public RSAKeySet GetRSAKeySet()
        {
            return new RSAKeySet(_publicKey, _privateKey);
        }

        public void CreateKeySet()
        {
            rsaCryptoServiceProvider = new RSACryptoServiceProvider();

            _publicKey = rsaCryptoServiceProvider.ExportParameters(false);
            _privateKey = rsaCryptoServiceProvider.ExportParameters(true);
        }
    }
}

