using System;
using System.Collections.Generic;
using System.Text;

/*
 * Copyright (C) 2011 Dextrey
 * Taking credit of this source code is strictly prohibited
 */

namespace SecureSocketProtocol2.Encryptions
{
    public class PolyDexMin3
    {
        internal byte[] key;
        public PolyDexMin3()
        {

        }

        public byte[] Encrypt(byte[] plain)
        {
            byte[] expandedKey = ExpandKey(key, plain.Length);
            byte[] wholeState = plain;
            byte magic = (byte)new Random().Next(byte.MaxValue);
            Array.Resize(ref wholeState, plain.Length + 1);
            wholeState[wholeState.Length - 1] = magic;

            for (int i = 0; i < wholeState.Length - 1; i++)
            {
                wholeState[i] = (byte)(wholeState[i] ^ expandedKey[i] ^ magic);
            }

            return wholeState;
        }

        public byte[] Decrypt(byte[] plain)
        {
            byte[] expandedKey = ExpandKey(key, plain.Length);
            byte[] wholeState = plain;
            byte magic = plain[plain.Length - 1];
            Array.Resize(ref wholeState, wholeState.Length - 1);

            for (int i = 0; i < wholeState.Length; i++)
            {
                wholeState[i] = (byte)(wholeState[i] ^ magic ^ expandedKey[i]);
            }

            return wholeState;
        }
        /// <summary>
        /// Performs DexCryptMin key expansion algorithm on variable length input key
        /// </summary>
        /// <param name="key">Input key</param>
        /// <param name="length">Count of output keystream bytes</param>
        /// <returns>Expanded keystream</returns>
        private byte[] ExpandKey(byte[] key, int length)
        {
            if (key.Length >= length) return key;
            byte[] rconst = BitConverter.GetBytes(Math.Round(Math.PI, 3));
            byte[] result = new byte[length];
            Buffer.BlockCopy(key, 0, result, 0, key.Length);
            // init round (fill all remaining bytes)
            for (int i = key.Length; i < length; i++)
            {
                // x[i] = ((k[i - len(k)) % len(k)] + x[i - 1]) % 256
                result[i] = (byte)((key[(i - key.Length) % key.Length] ^ (result[i - 1])) % 256);
            }

            // main rounds (process all bytes)
            for (int round = 0; round < 2; round++)
            {
                result[0] = (byte)(result[0] ^ rconst[round]);
                for (int i = 1; i < result.Length; i++)
                {
                    // x[i] = ((x[i] ^ (rcon[r] << (i % 3))) ^ x [i - 1]) % 256
                    result[i] = (byte)(((result[i] ^ (byte)(rconst[round] << (i % 4))) ^ result[i - 1]) % 256);
                }
            }
            return result;
        }
    }
}