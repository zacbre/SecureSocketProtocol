using System;
using System.Collections.Generic;
using System.Text;

/*
 * Copyright (C) 2011 Dextrey
 * Taking credit of this source code is strictly prohibited
 */

namespace SecureSocketProtocol2.Encryptions
{
    public class PolyAES
    {
        const int saltSize = 32;
        internal System.Security.Cryptography.SymmetricAlgorithm algo;
        internal System.Security.Cryptography.RNGCryptoServiceProvider rngAlgo;
        internal byte[] salt;
        internal byte[] key;

        public PolyAES()
        {
            this.algo = new System.Security.Cryptography.RijndaelManaged();
            this.algo.Mode = System.Security.Cryptography.CipherMode.CBC;
            this.rngAlgo = new System.Security.Cryptography.RNGCryptoServiceProvider();
        }

        public void InitializeSecureParameters(byte[] key)
        {
            // init rijndael IV
            this.algo.GenerateIV();
            salt = new byte[saltSize];
            rngAlgo.GetBytes(salt);
            System.Security.Cryptography.Rfc2898DeriveBytes pwDeriveAlg = new System.Security.Cryptography.Rfc2898DeriveBytes(key, salt, 2000);
            this.algo.Key = pwDeriveAlg.GetBytes(32);
            this.key = key;
        }

        private void LoadSecureParameters(byte[] key, byte[] encIv, byte[] encSalt)
        {
            this.algo.IV = encIv;
            this.salt = encSalt;
            System.Security.Cryptography.Rfc2898DeriveBytes pwDeriveAlg = new System.Security.Cryptography.Rfc2898DeriveBytes(key, salt, 2000);
            this.algo.Key = pwDeriveAlg.GetBytes(32);
        }

        public byte[] Encrypt(byte[] plainText)
        {
            int OriginalSize = plainText.Length;
            System.Security.Cryptography.ICryptoTransform encTransform = algo.CreateEncryptor();
            byte[] result = ConcatDataToCipherText(ConcatDataToCipherText(encTransform.TransformFinalBlock(plainText, 0, plainText.Length), salt), algo.IV);

            List<byte> ret = new List<byte>();
            ret.AddRange(BitConverter.GetBytes(OriginalSize));
            ret.AddRange(result);
            return ret.ToArray();
        }

        public byte[] Decrypt(byte[] cipherText)
        {
            int OriginalSize = BitConverter.ToInt32(cipherText, 0);
            Array.Copy(cipherText, 4, cipherText, 0, cipherText.Length - 4);
            Array.Resize(ref cipherText, cipherText.Length - 4);

            byte[] cipherTextWithSalt = new byte[1];
            byte[] encSalt = new byte[1];
            byte[] origCipherText = new byte[1];
            byte[] encIv = new byte[1];

            SliceCipherTextIntoParts(cipherText, 16, ref cipherTextWithSalt, ref encIv);
            SliceCipherTextIntoParts(cipherTextWithSalt, saltSize, ref origCipherText, ref encSalt);
            LoadSecureParameters(key, encIv, encSalt);
            System.Security.Cryptography.ICryptoTransform decTransform = algo.CreateDecryptor();
            byte[] plainText = decTransform.TransformFinalBlock(origCipherText, 0, origCipherText.Length);
            Array.Resize(ref plainText, OriginalSize);
            return plainText;
        }

        private byte[] ConcatDataToCipherText(byte[] cipherText, byte[] iv)
        {
            int origLength = cipherText.Length;
            Array.Resize(ref cipherText, cipherText.Length + iv.Length);
            Buffer.BlockCopy(iv, 0, cipherText, origLength, iv.Length);
            return cipherText;
        }
        private void SliceCipherTextIntoParts(byte[] cipherText, int secondPartLen, ref byte[] origCipherText, ref byte[] iv)
        {
            Array.Resize(ref iv, secondPartLen);
            Buffer.BlockCopy(cipherText, (int)(cipherText.Length - secondPartLen), iv, 0, secondPartLen);
            Array.Resize(ref origCipherText, (int)(cipherText.Length - secondPartLen));
            Buffer.BlockCopy(cipherText, 0, origCipherText, 0, (int)(cipherText.Length - secondPartLen));
        }
    }
}
