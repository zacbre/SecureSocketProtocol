using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

/*
*  HC-128 stream cipher implementation by 0xDEADDEAD
*  Code (not algorithm): Copyright (C) 2011 0xDEADDEAD
*/

namespace SecureSocketProtocol2.Encryptions
{
    public class HC128
    {
        private object ProcessLock = new object();
        // state
        private UInt32[] _P;
        private UInt32[] _Q;
        private byte[] _key;
        private byte[] _iv;
        private UInt32 _count = 0;

        /// <summary>
        /// Initialize a new instance of HC-128 stream cipher using specified parameters
        /// </summary>
        /// <param name="key">Key (128 bits)</param>
        /// <param name="iv">IV (128 bits)</param>
        public HC128(byte[] key, byte[] iv)
        {
            _key = key;
            _iv = iv;
        }

        public byte[] Encrypt(byte[] data)
        {
            lock (ProcessLock)
            {
                int OriginalSize = data.Length;
                InitState();
                byte[] keyStream = new byte[data.Length + (data.Length % 4)];

                for (int i = 0; i < keyStream.Length / 4; i++)
                {
                    byte[] keyB = BitConverter.GetBytes(GenerateKeyData());
                    Buffer.BlockCopy(keyB, 0, keyStream, i * 4, 4);
                }

                byte[] result = new byte[data.Length];

                for (int i = 0; i < data.Length; i++)
                {
                    result[i] = (byte)(data[i] ^ keyStream[i]);
                }
                List<byte> ret = new List<byte>();
                ret.AddRange(BitConverter.GetBytes(OriginalSize));
                ret.AddRange(result);
                return ret.ToArray();
            }
        }
        public byte[] Decrypt(byte[] data)
        {
            lock (ProcessLock)
            {
                int OriginalSize = BitConverter.ToInt32(data, 0);
                Array.Copy(data, 4, data, 0, data.Length - 4);
                Array.Resize(ref data, data.Length - 4);

                InitState();
                byte[] keyStream = new byte[data.Length + (data.Length % 4)];

                for (int i = 0; i < keyStream.Length / 4; i++)
                {
                    byte[] keyB = BitConverter.GetBytes(GenerateKeyData());
                    Buffer.BlockCopy(keyB, 0, keyStream, i * 4, 4);
                }

                byte[] result = new byte[data.Length];
                for (int i = 0; i < data.Length; i++)
                {
                    result[i] = (byte)(data[i] ^ keyStream[i]);
                }
                Array.Resize(ref result, OriginalSize);
                return result;
            }
        }



        /// <summary>
        /// Initialize cipher state
        /// </summary>
        private void InitState()
        {
            if (_key.Length != 16)
                throw new CryptographicException("invalid key size");

            if (_iv.Length != 16)
                throw new CryptographicException("invalid IV size");

            _count = 0;

            _P = new uint[512];
            _Q = new uint[512];
            UInt32[] KP = new uint[4];
            UInt32[] IVP = new uint[4];
            UInt32[] W = new uint[1280];

            KP[0] = BitConverter.ToUInt32(_key, 0);
            KP[1] = BitConverter.ToUInt32(_key, 4);
            KP[2] = BitConverter.ToUInt32(_key, 8);
            KP[3] = BitConverter.ToUInt32(_key, 12);

            IVP[0] = BitConverter.ToUInt32(_iv, 0);
            IVP[1] = BitConverter.ToUInt32(_iv, 4);
            IVP[2] = BitConverter.ToUInt32(_iv, 8);
            IVP[3] = BitConverter.ToUInt32(_iv, 12);

            for (int i = 0; i < 8; i++)
                W[i] = KP[i % 4];

            for (int i = 0; i < 8; i++)
                W[i + 8] = IVP[i % 4];

            for (int i = 16; i < 1280; i++)
                W[i] = (uint)(F2(W[i - 2]) + W[i - 7] + F1(W[i - 15]) + W[i - 16] + i);

            for (int i = 0; i < 512; i++)
                _P[i] = W[i + 256];

            for (int i = 0; i < 512; i++)
                _Q[i] = W[i + 768];

            for (int i = 0; i < 512; i++)
                _P[i] = (_P[i] +
               G1(_P[MinMod512((uint)i, 3)], _P[MinMod512((uint)i, 10)], _P[MinMod512((uint)i, 511)]))
                ^ H1(_P[MinMod512((uint)i, 12)]);

            for (int i = 0; i < 512; i++)
                _Q[i] = (_Q[i] +
               G2(_Q[MinMod512((uint)i, 3)], _Q[MinMod512((uint)i, 10)], _Q[MinMod512((uint)i, 511)]))
                ^ H2(_Q[MinMod512((uint)i, 12)]);

        }

        /// <summary>
        /// Generate a key byte
        /// </summary>
        /// <returns>Generated dword</returns>
        private UInt32 GenerateKeyData()
        {
            uint j = _count % 512;
            uint result = 0;
            if ((_count % 1024) < 512)
            {
                _P[j] = _P[j] +
                G1(_P[MinMod512(j, 3)], _P[MinMod512(j, 10)], _P[MinMod512(j, 511)]);

                result = H1(_P[MinMod512(j, 12)]) ^ _P[j];
            }
            else
            {
                _Q[j] = _Q[j] +
                G2(_Q[MinMod512(j, 3)], _Q[MinMod512(j, 10)], _Q[MinMod512(j, 511)]);

                result = H2(_Q[MinMod512(j, 12)]) ^ _Q[j];
            }
            _count++;
            return result;
        }

        /// <summary>
        /// a-b mod 512
        /// </summary>
        private UInt32 MinMod512(UInt32 a, UInt32 b)
        {
            return (a - b) % 512;
        }

        private UInt32 F1(UInt32 x)
        {
            return RollRight(x, 7) ^ RollRight(x, 18) ^ (x >> 3);
        }

        private UInt32 F2(UInt32 x)
        {
            return RollRight(x, 17) ^ RollRight(x, 19) ^ (x >> 10);
        }

        private UInt32 G1(UInt32 x, UInt32 y, UInt32 z)
        {
            return (RollRight(x, 10) ^ RollRight(z, 23)) + RollRight(y, 8);
        }

        private UInt32 G2(UInt32 x, UInt32 y, UInt32 z)
        {
            return (RollLeft(x, 10) ^ RollLeft(z, 23)) + RollLeft(y, 8);
        }

        private UInt32 H1(UInt32 x)
        {
            return _Q[(byte)x] + _Q[256 + (byte)(x >> 16)];
        }

        private UInt32 H2(UInt32 x)
        {
            return _P[(byte)x] + _P[256 + (byte)(x >> 16)];
        }

        private UInt32 RollRight(UInt32 x, int n)
        {
            return ((x >> n) ^ (x << (32 - n)));
        }

        private UInt32 RollLeft(UInt32 x, int n)
        {
            return ((x << n) ^ (x >> (32 - n)));
        }
    }
}
