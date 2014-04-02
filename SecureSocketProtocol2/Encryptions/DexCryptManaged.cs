using System;
using System.Collections.Generic;
using System.Text;

/*
 * Copyright (C) 2011 Dextrey
 * Taking credit of this source code is strictly prohibited
 *
 * Implements DexCrypt symmetric algorithm
 * 256-bit key size
 * 128-bit block size
 */

namespace SecureSocketProtocol2.Encryptions
{
    public class DexCryptManaged
    {
        internal byte[] key;
        internal byte[] iv;

        public DexCryptManaged()
        {

        }

        /// <summary>
        /// Encrypt plaintext using CBC cipher mode
        /// </summary>
        /// <param name="plaintext">Data to encrypt</param>
        /// <param name="key">256-bit (32 byte) key</param>
        /// <param name="iv">128-bit Initialization Vector</param>
        /// <returns>Encrypted data</returns>
        public byte[] Encrypt(byte[] plaintext)
        {
            int OriginalSize = plaintext.Length;
            if (iv.Length != 128 / 8)
            {
                throw new System.Security.Cryptography.CryptographicException("Invalid IV size");
            }
            if (key.Length != 256 / 8)
            {
                throw new System.Security.Cryptography.CryptographicException("Invalid key size");
            }
            List<byte[]> roundKeys = GenerateRoundKeys(key);
            byte[] plain = PadToModulo128(plaintext);
            byte[] result = new byte[plain.Length];
            byte[] lastBlock = (byte[])iv.Clone();
            byte[] buffer = new byte[16];

            for (int i = 0; i < (plain.Length / 16); i++)
            {
                Buffer.BlockCopy(plain, i * 16, buffer, 0, 16); // get block to be processed
                buffer = Cipher(XorRange(buffer, lastBlock), roundKeys); // apply block cipher
                Buffer.BlockCopy(buffer, 0, lastBlock, 0, 16); // copy ciphertext into CBC last block
                Buffer.BlockCopy(buffer, 0, result, i * 16, 16); // add ciphertext into output
            }
            List<byte> ret = new List<byte>();
            ret.AddRange(BitConverter.GetBytes(OriginalSize));
            ret.AddRange(result);
            return ret.ToArray();
        }

        /// <summary>
        /// Decrypts plaintext using CBC cipher mode
        /// </summary>
        /// <param name="plaintext">Data to decrypt</param>
        /// <param name="key">256-bit (32 byte) key</param>
        /// <param name="iv">128-bit Initialization Vector</param>
        /// <returns>Decrypted data</returns>
        public byte[] Decrypt(byte[] plain)
        {
            int OriginalSize = BitConverter.ToInt32(plain, 0);
            Array.Copy(plain, 4, plain, 0, plain.Length - 4);
            Array.Resize(ref plain, plain.Length - 4);

            if (iv.Length != 128 / 8)
            {
                throw new System.Security.Cryptography.CryptographicException("Invalid IV size");
            }
            if (key.Length != 256 / 8)
            {
                throw new System.Security.Cryptography.CryptographicException("Invalid key size");
            }
            List<byte[]> roundKeys = GenerateRoundKeys(key);
            byte[] result = new byte[plain.Length];
            byte[] lastBlock = (byte[])iv.Clone();
            byte[] buffer = new byte[16];
            byte[] cipherBuffer = new byte[16];

            for (int i = 0; i < (plain.Length / 16); i++)
            {
                Buffer.BlockCopy(plain, i * 16, buffer, 0, 16); // get block to be processed
                Buffer.BlockCopy(buffer, 0, cipherBuffer, 0, 16); // copy it into temp buffer for CBC XOR
                buffer = XorRange(Cipher(buffer, roundKeys, true), lastBlock); // block cipher and XOR
                Buffer.BlockCopy(cipherBuffer, 0, lastBlock, 0, 16); // set ciphered text into CBC last block
                Buffer.BlockCopy(buffer, 0, result, i * 16, 16); // add plaintext into result
            }
            byte[] ret = RemovePaddingToModulo128(result); // remove pad
            Array.Resize(ref ret, OriginalSize);
            return ret;
        }

        private byte[] PadToModulo128(byte[] plaintext)
        {
            // plaintext + 128 bits (all are zero) + enough bits to get overall length modulo 128 bits
            // last 4 bytes are signed integer length of original plaintext in bytes
            byte[] result = new byte[plaintext.Length + 16 + (16 - (plaintext.Length % 16))];
            Buffer.BlockCopy(plaintext, 0, result, 0, plaintext.Length);
            byte[] lengthBuffer = BitConverter.GetBytes(plaintext.Length);
            Buffer.BlockCopy(lengthBuffer, 0, result, result.Length - 4, 4);
            return result;
        }
        private byte[] RemovePaddingToModulo128(byte[] paddedText)
        {
            byte[] buffer = new byte[BitConverter.ToInt32(paddedText, paddedText.Length - 4)];
            Buffer.BlockCopy(paddedText, 0, buffer, 0, buffer.Length);
            return buffer;
        }
        private byte[] Cipher(byte[] plain, List<byte[]> roundKeys, bool reverse = false)
        {
            const int blockSize = 128 / 8;

            if (plain.Length != blockSize)
            {
                throw new System.Security.Cryptography.CryptographicException("Invalid plaintext size");
            }
            if (!reverse)
            {
                return Enc(plain, roundKeys.ToArray());
            }
            else
            {
                return Dec(plain, roundKeys.ToArray());
            }

        }
        /// <summary>
        /// Actual block cipher
        /// </summary>
        /// <param name="plain">Plaintext block</param>
        /// <param name="roundKeys">32 round keys</param>
        /// <returns>Ciphertext block</returns>
        private byte[] Enc(byte[] plain, byte[][] roundKeys)
        {
            byte[] state = new byte[16];
            state = plain;

            byte[][] rows = new byte[4][];
            for (int x = 0; x < 4; x++)
            {
                rows[x] = new byte[4];
            }

            int keyConstant2 = 0;
            for (int rk = 0; rk < 16; rk++)
            {
                keyConstant2 += roundKeys[0][rk];
            }

            for (int round = 0; round < 32; round++)
            {
                // RollRows -> SBOX -> XOR -> RollColumns -> RollState
                int keyConstant = roundKeys[round][0];
                for (int rk = 1; rk < 16; rk++)
                {
                    keyConstant += roundKeys[round][rk];
                    keyConstant /= 2;
                }

                // RollRows
                // 1 X X X X     3 X X X X
                // 2 X X X X ->  4 X X X X
                // 3 X X X X     1 X X X X
                // 4 X X X X     2 X X X X
                Buffer.BlockCopy(state, 0, rows[0], 0, 4);
                Buffer.BlockCopy(state, 4, rows[1], 0, 4);
                Buffer.BlockCopy(state, 8, rows[2], 0, 4);
                Buffer.BlockCopy(state, 12, rows[3], 0, 4);
                rows = RollArray(rows, (round) % 4);
                Buffer.BlockCopy(rows[0], 0, state, 0, 4);
                Buffer.BlockCopy(rows[1], 0, state, 4, 4);
                Buffer.BlockCopy(rows[2], 0, state, 8, 4);
                Buffer.BlockCopy(rows[3], 0, state, 12, 4);

                // SBOX
                ApplySBox(state);

                // XOR
                state = XorRange(state, roundKeys[round]);

                // RollColumns
                // 1 2 3 4     3 4 1 2
                // X X X X     X X X X
                // X X X X ->  X X X X
                // X X X X     X X X X
                // X X X X     X X X X
                // and each column is rotated vertically

                rows[0][0] = state[0];
                rows[0][1] = state[4];
                rows[0][2] = state[8];
                rows[0][3] = state[12];

                rows[1][0] = state[1];
                rows[1][1] = state[5];
                rows[1][2] = state[9];
                rows[1][3] = state[13];

                rows[2][0] = state[2];
                rows[2][1] = state[6];
                rows[2][2] = state[10];
                rows[2][3] = state[14];

                rows[3][0] = state[3];
                rows[3][1] = state[7];
                rows[3][2] = state[11];
                rows[3][3] = state[15];

                rows = RollArray(rows, (round + keyConstant + keyConstant2) % 4);

                state[0] = rows[0][0];
                state[4] = rows[0][1];
                state[8] = rows[0][2];
                state[12] = rows[0][3];

                state[1] = rows[1][0];
                state[5] = rows[1][1];
                state[9] = rows[1][2];
                state[13] = rows[1][3];

                state[2] = rows[2][0];
                state[6] = rows[2][1];
                state[10] = rows[2][2];
                state[14] = rows[2][3];

                state[3] = rows[3][0];
                state[7] = rows[3][1];
                state[11] = rows[3][2];
                state[15] = rows[3][3];

                // Rollstate
                state = RollArray(state, round % 4);
            }

            return state;
        }
        /// <summary>
        /// Decrypt block cipher
        /// </summary>
        /// <param name="plain">Ciphertext</param>
        /// <param name="roundKeys">32 round keys</param>
        /// <returns>Plaintext block</returns>
        private byte[] Dec(byte[] plain, byte[][] roundKeys)
        {
            byte[] state = new byte[16]; ;
            state = plain;

            byte[][] rows = new byte[4][];
            for (int x = 0; x < 4; x++)
            {
                rows[x] = new byte[4];
            }

            // Generate quite low-sec KeyConstant from first RoundKey
            int keyConstant2 = 0;
            for (int rk = 0; rk < 16; rk++)
            {
                keyConstant2 += roundKeys[0][rk];
            }

            for (int round = 31; round >= 0; round--)
            {

                // RollState -> RollColumns -> XOR -> SBOX -> RollRows

                // generate RoundKey specific constant for roll
                int keyConstant = roundKeys[round][0];
                for (int rk = 1; rk < 16; rk++)
                {
                    keyConstant += roundKeys[round][rk];
                    keyConstant /= 2;
                }
                // Rollstate
                state = RollArray(state, (0 - round) % 4);

                // RollColumns
                // 1 2 3 4     3 4 1 2
                // X X X X     X X X X
                // X X X X ->  X X X X
                // X X X X     X X X X
                // X X X X     X X X X
                // and each column is rotated vertically

                rows[0][0] = state[0];
                rows[0][1] = state[4];
                rows[0][2] = state[8];
                rows[0][3] = state[12];

                rows[1][0] = state[1];
                rows[1][1] = state[5];
                rows[1][2] = state[9];
                rows[1][3] = state[13];

                rows[2][0] = state[2];
                rows[2][1] = state[6];
                rows[2][2] = state[10];
                rows[2][3] = state[14];

                rows[3][0] = state[3];
                rows[3][1] = state[7];
                rows[3][2] = state[11];
                rows[3][3] = state[15];

                rows = RollArray(rows, (0 - round - keyConstant - keyConstant2) % 4);

                state[0] = rows[0][0];
                state[4] = rows[0][1];
                state[8] = rows[0][2];
                state[12] = rows[0][3];

                state[1] = rows[1][0];
                state[5] = rows[1][1];
                state[9] = rows[1][2];
                state[13] = rows[1][3];

                state[2] = rows[2][0];
                state[6] = rows[2][1];
                state[10] = rows[2][2];
                state[14] = rows[2][3];

                state[3] = rows[3][0];
                state[7] = rows[3][1];
                state[11] = rows[3][2];
                state[15] = rows[3][3];

                // XOR
                state = XorRange(state, roundKeys[round]);


                // SBOX
                ApplySBox(state, true);

                // RollRows
                Buffer.BlockCopy(state, 0, rows[0], 0, 4);
                Buffer.BlockCopy(state, 4, rows[1], 0, 4);
                Buffer.BlockCopy(state, 8, rows[2], 0, 4);
                Buffer.BlockCopy(state, 12, rows[3], 0, 4);
                rows = RollArray(rows, (0 - round) % 4);
                Buffer.BlockCopy(rows[0], 0, state, 0, 4);
                Buffer.BlockCopy(rows[1], 0, state, 4, 4);
                Buffer.BlockCopy(rows[2], 0, state, 8, 4);
                Buffer.BlockCopy(rows[3], 0, state, 12, 4);
            }
            return state;
        }
        /// <summary>
        /// Rotate array (circle) by count and direction
        /// </summary>
        /// <typeparam name="T">Type of array</typeparam>
        /// <param name="sarray">Array to rotate</param>
        /// <param name="count">Count and direction</param>
        /// <returns>Rotated array</returns>
        private T[] RollArray<T>(T[] sarray, int count)
        {
            T[] array = (T[])sarray.Clone();
            if (count < 0)
            {
                Array.Reverse(array);
            }

            for (int x = 0; x < Math.Abs(count); x++)
            {
                T[] result = new T[array.Length];
                T last = array[array.Length - 1];
                for (int i = 0; i < array.Length - 1; i++)
                {
                    result[i + 1] = array[i];
                }
                result[0] = last;
                array = (T[])result.Clone();
            }
            if (count < 0)
            {
                Array.Reverse(array);
            }
            return array;
        }
        /// <summary>
        /// DexCrypt roundkey derivation algorithm
        /// </summary>
        /// <param name="seedKey">Main 256-bit key</param>
        /// <returns>32 round keys</returns>
        private List<byte[]> GenerateRoundKeys(byte[] seedKey)
        {
            // seedkey.Length = 32 bytes = 256 bits
            List<byte[]> roundKeys = new List<byte[]>();

            byte iter = 0x01;

            // round constants
            byte[] rconst = new byte[] { 0x77, 0xd3, 0x25, 0xfe, 0x0c, 0x7b, 0x43, 0x10, 0x56, 0xc8, 0xd4, 0x15, 0x17, 0x62, 0xbd, 0xdd,
                0x89, 0xa8, 0x78, 0x38, 0xa9, 0xe0, 0x4f, 0xf0, 0x70, 0x88, 0xa6, 0x3b, 0x4a, 0x57, 0x74, 0x33 };

            for (int index = 0; index < 32; index++)
            {
                byte[] buffer = new byte[16]; // first half
                byte[] secondHalf = new byte[16]; // second half
                byte[] oldFirstHalf = new byte[16]; // first half of previous round key

                // buffer = first 16 bytes
                // secondHalf = last 16 bytes
                Buffer.BlockCopy(seedKey, 0, buffer, 0, 16);
                Buffer.BlockCopy(seedKey, 16, secondHalf, 0, 16);

                if (index != 0) // if not first round copy last round key into oldFirstHalf
                {
                    Buffer.BlockCopy(roundKeys[index - 1], 0, oldFirstHalf, 0, 16);
                }

                // for each byte in second half xor by iterator shift 1 to right then modulo round constant
                for (int it = 0; it < secondHalf.Length; it++)
                {
                    secondHalf[it] = (byte)((((secondHalf[it]) ^ iter) >> 1) % rconst[index]); // shift halve
                    iter++;
                }
                buffer = XorRange(buffer, secondHalf); // xor with second half
                buffer = XorRange(buffer, oldFirstHalf); // xor with old round key
                ApplySBox(buffer);
                roundKeys.Add(buffer);

            }
            return roundKeys;
        }

        private byte[] XorRange(byte[] first, byte[] second)
        {
            byte[] result = new byte[first.Length];
            if (first.Length != second.Length)
            {
                throw new ArgumentException("Lengths of arrays must match");
            }
            for (int i = 0; i < first.Length; i++) result[i] = (byte)(first[i] ^ second[i]);
            return result;
        }

        private void ApplySBox(byte[] source, bool inverse = false)
        {
            if (!inverse)
            {
                for (int i = 0; i < source.Length; i++)
                {
                    source[i] = sbox[source[i]];
                }
            }
            else
            {

                for (int i = 0; i < source.Length; i++)
                {
                    source[i] = invSbox[source[i]];
                }
            }
        }

        private byte[] sbox =
        new byte[] {
           0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
           0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
           0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
           0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
           0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
           0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
           0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
           0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
           0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
           0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
           0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
           0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
           0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
           0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
           0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
           0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
        };
        private byte[] invSbox = new byte[] {
           0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
           0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
           0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
           0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
           0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
           0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
           0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
           0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
           0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
           0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
           0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
           0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
           0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
           0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
           0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
           0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
        };
    }
}
