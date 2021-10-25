using System;
using System.IO;
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
        /// Encrypts data with the RSA algorithm. Prior to calling this function, either CreateKeySet(), ImportRSAPublicKey(...), or ImportRSAPrivateKey(...) must have been called. 
        /// </summary>
        /// <see cref="CreateKeySet"/>
        /// <see cref="ImportRSAPublicKey"/>
        /// <see cref="ImportRSAPrivateKey"/>
        /// <param name="text">Text to be encrypted.</param>
        /// <returns>Text that has been encrypted with the RSA algorithm and converted to Base64.</returns>
        public string RSAEncryptIntoBase64(string text)
        {
            var data = Encoding.UTF8.GetBytes(text);
            var cypher = rsaCryptoServiceProvider.Encrypt(data, false);

            return Convert.ToBase64String(cypher);
        }

        /// <summary>
        /// Decrypts data in Base64 format with the RSA algorithm. Prior to calling this function, either CreateKeySet(), or ImportRSAPrivateKey(...) must have been called. 
        /// </summary>
        /// <see cref="CreateKeySet"/>
        /// <see cref="ImportRSAPrivateKey"/>
        /// <param name="base64Cypher">A string of Base64-Encoded RSA cypher.</param>
        /// <returns>The decrypted data, which is the original plain text before encryption.</returns>
        public string RSADecryptFromBase64String(string base64Cypher)
        {
            var encodedBytes = Convert.FromBase64String(base64Cypher);

            var decodedBytes = rsaCryptoServiceProvider.Decrypt(encodedBytes, false);

            return Encoding.UTF8.GetString(decodedBytes);
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
        /// Exports the private-key portion of the current key in an xml serialized version of the PKCS#1 RSAPrivateKey format, converted to PEM format.
        /// </summary>
        /// <returns>A string containing an xml serialized version of the PKCS#1 RSAPrivateKey representation of this key</returns>
        public string ExportRSAPrivateKeyPEMString()
        {
            var outputstream = new StringWriter();

            ExportPrivateKey(rsaCryptoServiceProvider, outputstream);

            return outputstream.ToString();
        }

        /// <summary>
        /// Exports the public-key portion of the current key in an xml serialized version of the PKCS#1 RSAPublicKey format, converted to PEM format.
        /// </summary>
        /// <returns>A string containing an xml serialized version of the PKCS#1 RSAPublicKey representation of this key</returns>
        public string ExportRSAPublicKeyPEMString()
        {
            var outputstream = new StringWriter();

            ExportPublicKey(rsaCryptoServiceProvider, outputstream);

            return outputstream.ToString();
        }

        private static void ExportPublicKey(RSACryptoServiceProvider csp, TextWriter outputStream)
        {
            var parameters = csp.ExportParameters(false);
            using (var stream = new MemoryStream())
            {
                var writer = new BinaryWriter(stream);
                writer.Write((byte)0x30); // SEQUENCE
                using (var innerStream = new MemoryStream())
                {
                    var innerWriter = new BinaryWriter(innerStream);
                    innerWriter.Write((byte)0x30); // SEQUENCE
                    EncodeLength(innerWriter, 13);
                    innerWriter.Write((byte)0x06); // OBJECT IDENTIFIER
                    var rsaEncryptionOid = new byte[] { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
                    EncodeLength(innerWriter, rsaEncryptionOid.Length);
                    innerWriter.Write(rsaEncryptionOid);
                    innerWriter.Write((byte)0x05); // NULL
                    EncodeLength(innerWriter, 0);
                    innerWriter.Write((byte)0x03); // BIT STRING
                    using (var bitStringStream = new MemoryStream())
                    {
                        var bitStringWriter = new BinaryWriter(bitStringStream);
                        bitStringWriter.Write((byte)0x00); // # of unused bits
                        bitStringWriter.Write((byte)0x30); // SEQUENCE
                        using (var paramsStream = new MemoryStream())
                        {
                            var paramsWriter = new BinaryWriter(paramsStream);
                            EncodeIntegerBigEndian(paramsWriter, parameters.Modulus); // Modulus
                            EncodeIntegerBigEndian(paramsWriter, parameters.Exponent); // Exponent
                            var paramsLength = (int)paramsStream.Length;
                            EncodeLength(bitStringWriter, paramsLength);
                            bitStringWriter.Write(paramsStream.GetBuffer(), 0, paramsLength);
                        }
                        var bitStringLength = (int)bitStringStream.Length;
                        EncodeLength(innerWriter, bitStringLength);
                        innerWriter.Write(bitStringStream.GetBuffer(), 0, bitStringLength);
                    }
                    var length = (int)innerStream.Length;
                    EncodeLength(writer, length);
                    writer.Write(innerStream.GetBuffer(), 0, length);
                }

                var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length).ToCharArray();
                outputStream.WriteLine("-----BEGIN PUBLIC KEY-----");
                for (var i = 0; i < base64.Length; i += 64)
                {
                    outputStream.WriteLine(base64, i, Math.Min(64, base64.Length - i));
                }
                outputStream.WriteLine("-----END PUBLIC KEY-----");
            }
        }

        private static void ExportPrivateKey(RSACryptoServiceProvider csp, TextWriter outputStream)
        {
            if (csp.PublicOnly) throw new ArgumentException("CSP does not contain a private key", "csp");
            var parameters = csp.ExportParameters(true);
            using (var stream = new MemoryStream())
            {
                var writer = new BinaryWriter(stream);
                writer.Write((byte)0x30); // SEQUENCE
                using (var innerStream = new MemoryStream())
                {
                    var innerWriter = new BinaryWriter(innerStream);
                    EncodeIntegerBigEndian(innerWriter, new byte[] { 0x00 }); // Version
                    EncodeIntegerBigEndian(innerWriter, parameters.Modulus);
                    EncodeIntegerBigEndian(innerWriter, parameters.Exponent);
                    EncodeIntegerBigEndian(innerWriter, parameters.D);
                    EncodeIntegerBigEndian(innerWriter, parameters.P);
                    EncodeIntegerBigEndian(innerWriter, parameters.Q);
                    EncodeIntegerBigEndian(innerWriter, parameters.DP);
                    EncodeIntegerBigEndian(innerWriter, parameters.DQ);
                    EncodeIntegerBigEndian(innerWriter, parameters.InverseQ);
                    var length = (int)innerStream.Length;
                    EncodeLength(writer, length);
                    writer.Write(innerStream.GetBuffer(), 0, length);
                }

                var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length).ToCharArray();
                outputStream.WriteLine("-----BEGIN RSA PRIVATE KEY-----");
                // Output as Base64 with lines chopped at 64 characters
                for (var i = 0; i < base64.Length; i += 64)
                {
                    outputStream.WriteLine(base64, i, Math.Min(64, base64.Length - i));
                }
                outputStream.WriteLine("-----END RSA PRIVATE KEY-----");
            }
        }

        private static void EncodeLength(BinaryWriter stream, int length)
        {
            if (length < 0) throw new ArgumentOutOfRangeException("length", "Length must be non-negative");
            if (length < 0x80)
            {
                // Short form
                stream.Write((byte)length);
            }
            else
            {
                // Long form
                var temp = length;
                var bytesRequired = 0;
                while (temp > 0)
                {
                    temp >>= 8;
                    bytesRequired++;
                }
                stream.Write((byte)(bytesRequired | 0x80));
                for (var i = bytesRequired - 1; i >= 0; i--)
                {
                    stream.Write((byte)(length >> (8 * i) & 0xff));
                }
            }
        }

        private static void EncodeIntegerBigEndian(BinaryWriter stream, byte[] value, bool forceUnsigned = true)
        {
            stream.Write((byte)0x02); // INTEGER
            var prefixZeros = 0;
            for (var i = 0; i < value.Length; i++)
            {
                if (value[i] != 0) break;
                prefixZeros++;
            }
            if (value.Length - prefixZeros == 0)
            {
                EncodeLength(stream, 1);
                stream.Write((byte)0);
            }
            else
            {
                if (forceUnsigned && value[prefixZeros] > 0x7f)
                {
                    // Add a prefix zero to force unsigned if the MSB is 1
                    EncodeLength(stream, value.Length - prefixZeros + 1);
                    stream.Write((byte)0);
                }
                else
                {
                    EncodeLength(stream, value.Length - prefixZeros);
                }
                for (var i = prefixZeros; i < value.Length; i++)
                {
                    stream.Write(value[i]);
                }
            }
        }
    }
}

