using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Diagnostics;
using SecureSocketProtocol2.Network;

namespace SecureSocketProtocol2.Encryptions
{
    public enum HashAlgorithm { MD5, SHA1 }
    public class AesEncryption
    {
        public string Hash { get; private set; }
        public int PasswordIterations { get; private set; }
        public const int KeySize = 256;
        private Object locky = new Object();
        private RijndaelManaged SymmetricKey;
        private byte[] KeyBytes = new byte[0];
        private ICryptoTransform Encryptor;
        private ICryptoTransform Decryptor;
        private Connection connection;

        public byte[] key = new byte[]
        {
            158, 186, 66, 139, 236, 119, 250, 87, 146, 107, 104, 176, 111, 94, 132,
            210, 149, 70, 200, 228,  225, 123, 147, 81, 245, 250, 222, 217, 174, 176,
            120, 148, 230, 152, 88, 71, 205, 251, 50, 204, 76, 186, 224, 77, 227,
            228, 135, 203, 188, 229, 190, 233, 89, 93, 102, 227, 114, 159, 196, 112,
            128, 96, 110, 168, 127, 79, 194, 80, 248, 230, 121, 61, 66, 89, 58,
            191, 247, 223, 86, 240, 91, 201, 97, 182, 187, 115, 82, 180, 140, 138,
            52, 179, 198, 216, 161, 136, 170, 64, 86, 226
        };
        public byte[] salt = new byte[]
        {
            80, 222, 172, 114, 124, 187, 93, 143, 242, 101, 139, 128, 165, 254, 50, 225, 238, 4, 136, 83, 165, 135, 46, 168, 72, 254, 157, 246, 17, 202, 234, 133, 50, 153, 91,
            246, 57, 149, 134, 235, 67, 55, 206, 136, 112, 217, 146, 81, 175, 222, 49, 218, 191, 78, 234, 101, 163, 104, 39, 176, 150, 112, 10, 204, 163, 14, 239, 193, 230, 20,
            81, 227, 196, 33, 83, 186, 45, 246, 80, 97, 193, 163, 138, 254, 165, 108, 232, 202, 123, 213, 118, 48, 85, 113, 214, 73, 241, 212, 60, 221, 29, 123, 56, 118, 101,
            87, 82, 145, 220, 37, 196, 150, 251, 24, 243, 139, 74, 39, 229, 107, 244, 198, 76, 80, 130, 32, 210, 250, 82, 174, 157, 140, 45, 45, 163, 51, 227, 117, 68, 154,
            58, 119, 87, 20, 235, 213, 1, 209, 193, 183, 236, 212, 31, 59, 113, 10, 188, 12, 143, 228, 193, 13, 130, 182, 241, 65, 139, 71, 54, 78, 164, 165, 165, 56, 73,
            59, 111, 137, 62, 174, 117, 19, 126, 32, 199, 101, 139, 167, 63, 64, 233, 1, 221, 74, 179, 109, 201, 211, 234, 142, 237, 74, 99, 214, 163, 227, 215, 212, 225, 130,
            157, 59, 246, 85, 11, 160, 226, 122, 63, 10, 36, 36, 156, 205, 70, 112, 27, 54, 80, 50, 96, 231, 13, 106, 114, 158, 15, 42, 19, 90, 36, 200, 201, 156, 91,
            233, 254, 58, 156, 146, 56, 62, 195, 178, 160, 144, 238, 69, 16, 50, 197, 214, 61, 157, 28, 33, 43, 226, 140, 18, 172, 98, 213, 137, 119, 89, 46, 203, 120, 253,
            147, 107, 32, 71, 204, 165, 46, 7, 151, 223, 167, 232, 83, 73, 107, 103, 76, 74, 203, 226, 35, 175, 76, 243, 97, 179, 102, 103, 16, 135, 143, 208, 21, 170, 79,
            189, 125, 3, 37, 172, 77, 53, 72, 35, 166, 72, 81, 12, 254, 227, 252, 162, 15, 11, 110, 25, 205, 24, 195, 53, 131, 150, 29, 104, 133, 46, 53, 28, 94, 193,
            179, 37, 76, 176, 220, 45, 153, 161, 45, 110, 148, 159, 143, 22, 146, 174, 110, 243, 38, 28, 255, 241, 255, 44, 196, 73, 71, 140, 87, 211, 160, 63, 235, 234, 95,
            115, 155, 255, 182, 24, 76, 229, 59, 52, 77, 49, 158, 41, 141, 199, 7, 177, 168, 223, 33, 60, 149, 95, 150, 192, 156, 140, 190, 179, 153, 30, 131, 27, 232, 5,
            244, 212, 53, 56, 62, 70, 26, 187, 62, 43, 169, 241, 174, 115, 172, 118, 162, 43, 113, 132, 97, 137, 41, 121, 101, 80, 141, 163, 16, 38, 200, 102, 122, 79, 15,
            20, 73, 185, 243, 234, 190, 248, 36, 36, 201, 79, 51, 139, 10, 133, 242, 108, 186, 169, 21, 109, 12, 88, 211, 186, 76, 160, 70, 148, 19, 124, 255, 107, 173, 50,
            106, 95, 176, 8, 100, 202, 174, 151, 121, 85, 208, 229, 147, 129, 237, 208, 87, 31, 203, 230, 17, 202, 165, 217, 102, 226, 138, 3, 101, 69, 154, 120, 170, 144, 175,
            211, 99, 121, 96, 214, 216, 45, 61, 5, 72, 250, 212, 127, 114, 85, 164, 115, 8, 191, 243, 33, 131, 31, 229, 177, 2, 28, 61, 196, 249, 139, 179, 98, 242, 196,
            50, 152, 95, 110, 164, 126, 165, 57, 70, 133, 106, 220, 213, 161, 20, 78, 200, 32, 204, 221, 165, 156, 72, 51, 91, 95, 141, 184, 156, 93, 57, 127, 182, 39, 89,
            67, 166, 27, 52, 198, 29, 246, 141, 56, 187, 231, 223, 57, 226, 181, 46, 248, 130, 238, 166, 170, 254, 39, 162, 74, 26, 69, 38, 166, 15, 161, 51, 232, 41, 244,
            23, 30, 217, 242, 166, 110, 111, 225, 68, 129, 120, 240, 186, 152, 2, 55, 229, 98, 102, 130, 67, 212, 241, 17, 150, 249, 36, 221, 227, 84, 252, 104, 163, 138, 149,
            4, 48, 98, 27, 221, 78, 157, 226, 226, 82, 183, 68, 31, 208, 32, 69, 132, 129, 210, 197, 34, 233, 164, 91, 101, 13, 68, 22, 52, 180, 162, 157, 10, 201, 185,
            104, 94, 19, 80, 176, 240, 79, 246, 69, 185, 216, 177, 74, 149, 156, 196, 152, 27, 86, 83, 236, 55, 90, 127, 33, 84, 50, 226, 161, 204, 162, 73, 20, 12, 93,
            77, 95, 122, 1, 242, 214, 26, 41, 159, 68, 114, 223, 158, 47, 243, 101, 71, 222, 30, 73, 65, 166, 43, 66, 65, 183, 70, 20, 100, 74, 8, 6, 166, 33, 62,
            159, 11, 35, 80, 70, 164, 139, 56, 182, 8, 164, 214, 73, 13, 147, 96, 48, 161, 172, 174, 96, 44, 224, 39, 99, 112, 71, 204, 44, 87, 253, 30, 174, 113, 216,
            199, 45, 140, 55, 181, 214, 255, 153, 59, 100, 177, 136, 35, 11, 188, 173, 166, 220, 137, 131, 135, 101, 174, 46, 174, 2, 164, 48, 232, 207, 72, 238, 85, 14, 74,
            78, 84, 25, 119, 42, 82, 26, 75, 121, 189, 48, 73, 136, 91, 21, 224, 171, 24, 27, 149, 27, 25, 224, 59, 114, 35, 235, 185, 215, 198, 75, 183, 39, 43, 236,
            158, 254, 17, 234, 186, 182, 200, 48, 152, 206, 29, 177, 176, 118, 208, 159, 93, 116, 22, 18, 207, 243, 56, 255, 112, 247, 60, 148, 185, 5, 224, 103, 52, 235, 158,
            223, 56, 213, 59, 119, 195, 75, 141, 111, 201, 163, 26, 133, 204, 105, 75, 63, 71, 60, 61, 30, 22, 206, 233, 130, 190, 90, 182, 230, 91, 57, 131, 238, 87, 154,
            144, 222, 43, 230, 132, 207, 17, 176, 159, 58, 201, 37, 89, 78, 19, 32, 244, 46, 183, 69, 231, 108, 114, 182, 183, 174, 124, 54, 189, 28, 181, 70, 98, 220, 72,
            36, 144, 42, 142, 81, 249, 250, 218, 114, 57, 92, 177, 121, 159, 14, 109, 170, 255, 235, 101, 249, 235, 99, 163, 202, 194, 9, 54, 74, 37, 239, 79, 108, 90, 16,
            28, 146, 160, 23, 157, 73, 24, 230, 168
        };

        public byte[] IV = new byte[] { 160, 120, 103, 143, 17, 18, 77, 7, 56, 141, 28, 253, 120, 192, 216, 223 };

        public AesEncryption(Connection connection, HashAlgorithm hash, int PasswordIterations)
        {
            this.Hash = hash.ToString();
            this.PasswordIterations = PasswordIterations;
            this.connection = connection;
            RefreshKeys();
        }

        internal void RefreshKeys()
        {
            PasswordDeriveBytes DerivedPassword = new PasswordDeriveBytes(key, salt, Hash, PasswordIterations);
            this.KeyBytes = DerivedPassword.GetBytes(KeySize / 8);
            this.SymmetricKey = new RijndaelManaged();
            SymmetricKey.Mode = CipherMode.CBC;
            this.Encryptor = SymmetricKey.CreateEncryptor(KeyBytes, IV);
            this.Decryptor = SymmetricKey.CreateDecryptor(KeyBytes, IV);
        }

        public void Encrypt(NetworkPayloadWriter npw)
        {
            lock (locky)
            {
                npw.vStream.Position = connection.HEADER_SIZE;
                CryptoStream CryptoStream = new CryptoStream(npw.vStream, Encryptor, CryptoStreamMode.Write);
                CryptoStream.Write(npw.GetBuffer(), connection.HEADER_SIZE, npw.Length - connection.HEADER_SIZE);
                CryptoStream.FlushFinalBlock();
            }
        }

        public byte[] Encrypt(ref byte[] data, ref uint offset, ref uint length)
        {
            lock (locky)
            {
                using (MemoryStream inStream = new MemoryStream())
                {
                    CryptoStream CryptoStream = new CryptoStream(inStream, Encryptor, CryptoStreamMode.Write);
                    CryptoStream.Write(data, (int)offset, (int)length);
                    CryptoStream.FlushFinalBlock();
                    data = inStream.GetBuffer();
                    offset = 0;
                    length = (uint)inStream.Length;
                    return data;
                }
            }
        }

        public byte[] Decrypt(byte[] CipherText, ref uint offset, ref uint length)
        {
            lock (locky)
            {
                byte[] PlainTextBytes = new byte[length];
                using (MemoryStream MemStream = new MemoryStream(CipherText, (int)offset, (int)length))
                {
                    using (CryptoStream CryptoStream = new CryptoStream(MemStream, Decryptor, CryptoStreamMode.Read))
                    {
                        length = (uint)CryptoStream.Read(PlainTextBytes, 0, PlainTextBytes.Length);
                    }
                }
                return PlainTextBytes;
            }
        }
    }
}