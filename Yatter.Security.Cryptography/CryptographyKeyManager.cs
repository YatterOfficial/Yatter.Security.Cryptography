using System;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Serialization;

namespace Yatter.Security.Cryptography
{
    /// <summary>
    /// A Cryptography Key Manager that can generate Public and Private keys using the RSA algorithm, import and export RSA Public and Private keys, and encrypt and decrypt using those RSA Public and Private keys. Helper methods cater for RSA cyphers in Base64 string format, as well as the capacity to export RSA cyphers in Base64 format.
    /// </summary>
    public class CryptographyKeyManager
    {
        private RSACryptoServiceProvider rsaCryptoServiceProvider = new RSACryptoServiceProvider();

        /// <summary>
        /// The standard parameter for the RSA algorith, with only the public component.
        /// </summary>
        private RSAParameters _publicKey;

        /// <summary>
        /// The standard parameter for the RSA algorith, with both the public component and the private component.
        /// </summary>
        private RSAParameters _privateKey;

        public CryptographyKeyManager() { }

        /// <summary>
        /// Encrypts data with the RSA algorithm.
        /// </summary>
        /// <param name="text">Text to be encrypted.</param>
        /// <returns>Text that has been encrypted with the RSA algorithm.</returns>
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

        /// <summary>
        /// Encrypts data with the RSA algorithm.
        /// </summary>
        /// <param name="text">Text to be encrypted.</param>
        /// <returns>Text that has been encrypted with the RSA algorithm and converted to Base64.</returns>
        public string RSAEncryptBase64(string text)
        {
            var data = Encoding.Unicode.GetBytes(text);
            var cypher = rsaCryptoServiceProvider.Encrypt(data, false);

            return Convert.ToBase64String(cypher);
        }

        /// <summary>
        /// Decrypts data with the RSA algorithm.
        /// </summary>
        /// <param name="cypher">A string of RSA cypher.</param>
        /// <returns>The decrypted data, which is the original plain text before encryption.</returns>
        public string RSADecryptFromString(string cypher)
        {
            var encodedBytes = Convert.FromBase64String(cypher);

            var decodedBytes = rsaCryptoServiceProvider.Decrypt(encodedBytes, false);

            return Encoding.Unicode.GetString(decodedBytes);
        }

        /// <summary>
        /// Decrypts data in Base64 format with the RSA algorithm.
        /// </summary>
        /// <param name="base64Cypher">A string of Base64-Encoded RSA cypher.</param>
        /// <returns>The decrypted data, which is the original plain text before encryption.</returns>
        public string RSADecryptFromBase64String(string base64Cypher)
        {
            var encodedBytes = Convert.FromBase64String(base64Cypher);

            var decodedBytes = rsaCryptoServiceProvider.Decrypt(encodedBytes, false);

            return Encoding.Unicode.GetString(decodedBytes);
        }

        /// <summary>
        /// Imports the public key from a PKCS#1 RSAPublicKey structure after decryption, replacing the keys for this object.
        /// </summary>
        /// <param name="source"></param>
        /// <returns>bytes read</returns>
        public int ImportRSAPublicKey(ReadOnlySpan<byte> source)
        {
            int bytesRead;
            rsaCryptoServiceProvider.ImportRSAPublicKey(source, out bytesRead);

            return bytesRead;
        }

        /// <summary>
        /// Imports the public/private keypair from a PKCS#1 RSAPrivateKey structure after decryption, replacing the keys for this object.
        /// </summary>
        /// <param name="source"></param>
        /// <returns>bytes read</returns>
        public int ImportRSAPrivateKey(ReadOnlySpan<byte> source)
        {
            int bytesRead;
            rsaCryptoServiceProvider.ImportRSAPrivateKey(source, out bytesRead);

            return bytesRead;
        }


        /// <summary>
        /// Creates a public and private key as RSAParameters that can be exported, used to encrypt, and used to decrypt. Should not be called if either of a public key or private key have been imported.
        /// </summary>
        public void CreateKeySet()
        {
            _publicKey = rsaCryptoServiceProvider.ExportParameters(false);
            _privateKey = rsaCryptoServiceProvider.ExportParameters(true);
        }

        /// <summary>
        /// Exports the private-key portion of the current key in the PKCS#1 RSAPrivateKey format.
        /// </summary>
        /// <returns>A byte array containing the PKCS#1 RSAPrivateKey representation of this key</returns>
        public byte[] ExportRSAPrivateKeyBytes()
        {
            return rsaCryptoServiceProvider.ExportRSAPrivateKey();
        }

        /// <summary>
        /// Exports the public-key portion of the current key in the PKCS#1 RSAPublicKey format.
        /// </summary>
        /// <returns>A byte array containing the PKCS#1 RSAPublicKey representation of this key</returns>
        public byte[] ExportRSAPublicKeyBytes()
        {
            return rsaCryptoServiceProvider.ExportRSAPublicKey();
        }

        /// <summary>
        /// Exports the private-key portion of the current key in an xml serialized version of the PKCS#1 RSAPrivateKey format.
        /// </summary>
        /// <returns>A string containing an xml serialized version of the PKCS#1 RSAPrivateKey representation of this key</returns>
        public string ExportRSAPrivateKeyString()
        {
            var sw = new StringWriter();
            var xs = new XmlSerializer(typeof(RSAParameters));
            xs.Serialize(sw, _privateKey);
            return sw.ToString();
        }

        /// <summary>
        /// Exports the public-key portion of the current key in an xml serialized version of the PKCS#1 RSAPublicKey format.
        /// </summary>
        /// <returns>A string containing an xml serialized version of the PKCS#1 RSAPublicKey representation of this key</returns>
        public string ExportRSAPublicKeyString()
        {
            var sw = new StringWriter();
            var xs = new XmlSerializer(typeof(RSAParameters));
            xs.Serialize(sw, _publicKey);
            return sw.ToString();
        }
    }
}

