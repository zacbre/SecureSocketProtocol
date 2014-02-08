using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using SecureSocketProtocol2.Network;
using System.IO;

namespace SecureSocketProtocol2.Encryptions
{
    public class RSAEncryption
    {
        private System.Security.Cryptography.RSACryptoServiceProvider rsa;
        public string PrivateKey { get; internal set; }
        public string PublicKey { get; internal set; }
        public int EncChunkSize { get; private set; }
        public int DecChunkSize { get; private set; }
        public bool PkcsPadding { get; private set; }
        public int KeySize { get; private set; }

        public RSAParameters Parameters
        {
            get
            {
                return rsa.ExportParameters(false);
            }
        }

        public RSAEncryption(int KeySize, bool PkcsPadding = true)
        {
            this.rsa = new System.Security.Cryptography.RSACryptoServiceProvider(KeySize);
            this.PkcsPadding = PkcsPadding;
            this.KeySize = KeySize;
            this.DecChunkSize = (KeySize / 8);
            this.EncChunkSize = DecChunkSize / 2;
        }
        public RSAEncryption(int KeySize, string PublicKey, string PrivateKey, bool PkcsPadding = true)
        {
            this.rsa = new System.Security.Cryptography.RSACryptoServiceProvider(KeySize);
            this.PublicKey = PublicKey;
            this.PrivateKey = PrivateKey;
            this.PkcsPadding = PkcsPadding;
            this.KeySize = KeySize;
            this.DecChunkSize = (KeySize / 8);
            this.EncChunkSize = DecChunkSize / 2;
        }
        public RSAEncryption(int KeySize, byte[] Modulus, byte[] Exponent, bool PkcsPadding = true)
        {
            RSAParameters parameters = new RSAParameters();
            parameters.Exponent = Exponent;
            parameters.Modulus = Modulus;
            this.rsa = new RSACryptoServiceProvider(KeySize);
            this.rsa.ImportParameters(parameters);
            this.PkcsPadding = PkcsPadding;
        }

        public void GeneratePrivateKey()
        {
            this.PrivateKey = rsa.ToXmlString(true);
        }

        public void GeneratePublicKey()
        {
            this.PublicKey = rsa.ToXmlString(false);
        }

        public byte[] Encrypt(byte[] Data, int Offset, int Length)
        {
            lock (rsa)
            {
                int ExpectedSize = (KeySize / 8) * (Length / EncChunkSize);
                using (MemoryStream stream = new MemoryStream(Data.Length + ExpectedSize))
                {
                    int LengthLeft = Length;
                    if (PublicKey != null && PublicKey.Length > 0)
                    {
                        rsa.FromXmlString(PublicKey);
                    }

                    for (int i = Offset; i < Length; i += EncChunkSize)
                    {
                        int size = i + EncChunkSize < Length ? EncChunkSize : LengthLeft;

                        byte[] temp = new byte[size];
                        Array.Copy(Data, i, temp, 0, size);
                        byte[] encrypted = rsa.Encrypt(temp, PkcsPadding);
                        stream.Write(encrypted, 0, encrypted.Length);

                        if (LengthLeft >= EncChunkSize)
                            LengthLeft -= size;
                    }
                    return stream.ToArray();
                }
            }
        }

        public byte[] Decrypt(byte[] Data, int Offset, int Length)
        {
            if (Length % DecChunkSize != 0)
                throw new Exception("Invalid length");

            using (MemoryStream stream = new MemoryStream(Data.Length))
            {
                int LengthLeft = Length;

                if (PrivateKey != null && PrivateKey.Length > 0)
                {
                    rsa.FromXmlString(PrivateKey);
                }

                for (int i = Offset; i < Length; i += DecChunkSize)
                {
                    byte[] temp = new byte[DecChunkSize];
                    Array.Copy(Data, i, temp, 0, DecChunkSize);
                    byte[] decrypted = rsa.Decrypt(temp, PkcsPadding);
                    stream.Write(decrypted, 0, decrypted.Length);

                    if (LengthLeft >= DecChunkSize)
                        LengthLeft -= DecChunkSize;
                }
                return stream.ToArray();
            }
        }
    }
}