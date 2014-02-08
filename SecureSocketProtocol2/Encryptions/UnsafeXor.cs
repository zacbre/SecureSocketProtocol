using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Encryptions
{
    public unsafe class UnsafeXor
    {
        /*
         * features:
         * dynamic key
         * dynamic key can be enabled/disabled
         * key offset to make encrypted data more unique looking
        */ 


        public uint[] Key = new uint[]
        {
            0xAADF89, 0X7FAD9A, 0x87F8D9, 0x9D8A63, 0xA8D764, 0x9F8D7A, 0xD8A637,
            0x872328, 0x8989AD, 0x4D8912, 0x278394, 0xC89A9C, 0xDEADDD, 0xBEEFFF, 
            0x9F7D7A, 0x78178A, 0x89D7A7, 0x7D9A79, 0x78D789, 0x7D8A55, 0xAF6BD7, 
            0xD7A7D8, 0x8D79A2, 0x89A829, 0x536D9A, 0x7D87AA, 0xD1DAD1, 0x89D89A, 
            0x828199, 0x6F8ADF, 0xBC576F, 0xA56DFB, 0x5A786F, 0xA6D7BF, 0xA7DFB0, 
            0x8DA7D8, 0x7FC89A, 0xACFABD, 0xA678BF, 0x76BA89, 0xA76DFB, 0xA5BF67, 
            0x7C8A7D, 0x6FCDAF, 0x89A9FD, 0xABADF6, 0xA7DFBB, 0xBEEEEF, 0x6BA7FD, 
            0x898A9C, 0x79F8DA, 0xA56DF8, 0x5A768F, 0xABDF57, 0x6A7FD8, 0xBA768F, 
            0x23A54D, 0x69F8A6, 0x3A4BFD, 0xA5B76D, 0x5BA76D, 0x5AD76B, 0xAB86F7, 
            0x6CFA7D, 0x3F56CD, 0x6A78F9, 0x4AB56F, 0x78AB9D, 0x4ABDF7, 0xA768BF, 
            0x356CAF, 0x7869CF, 0x76ABCA, 0x7A89FD, 0x2BA45D, 0xA6FDB7, 0x786ABD, 
            0xF789CA, 0x890FCD, 0x8A90CD, 0x45A468, 0xA7DFB8, 0xABCDEF, 0x7AB89F, 
            0x786CFA, 0x67CFDA, 0x789ADF, 0xA578A9, 0x456BAF, 0xBABEEE, 0xA6BDFF, 
            0x89CFDA, 0x3F456D, 0x4AB56D, 0x6A8D7F, 0x7A8B9F, 0xA678DF, 0xA789FD,
        };

        private object ProcessLock = new object();
        internal uint[] decrypt_key;
        internal uint[] encrypt_key;
        public bool DynamicKey { get; private set; }
        private Random EncRnd = new Random();
        private Random DecRnd = new Random();

        public unsafe UnsafeXor(bool UseDynamicKey)
        {
            decrypt_key = new uint[Key.Length];
            encrypt_key = new uint[Key.Length];

            for (int i = 0; i < encrypt_key.Length; i++)
            {
                encrypt_key[i] = Key[i];
                decrypt_key[i] = Key[i];
            }
            this.DynamicKey = UseDynamicKey;
        }

        public unsafe UnsafeXor(uint[] _key, bool UseDynamicKey)
        {
            decrypt_key = new uint[Key.Length];
            encrypt_key = new uint[Key.Length];

            for (int i = 0; i < encrypt_key.Length; i++)
            {
                encrypt_key[i] = Key[i];
                decrypt_key[i] = Key[i];
            }
            for (int i = 0; i < _key.Length; i++)
            {
                encrypt_key[i % encrypt_key.Length] += (uint)((_key[i] * i) + _key.Length);
                decrypt_key[i % decrypt_key.Length] += (uint)((_key[i] * i) + _key.Length);
            }

            this.DynamicKey = UseDynamicKey;
        }

        public byte[] Encrypt(ref byte[] data, int offset, int length)
        {
            lock (ProcessLock)
            {
                if (data.Length <= 0 || length + offset > data.Length)
                    return data;

                byte ByteOffset = 0;// (byte)EncRnd.Next(10, 255);

                fixed (byte* x = &(data[offset]))
                {
                    byte* ptr = x;
                    Int32 BytesLeft = length & 3;
                    Int32 Loops = length >> 2;
                    uint temp = 0;

                    for (int i = 0; i < Loops; i++)
                    {
                        uint temp2 = *(uint*)ptr;
                        temp = temp2 ^ encrypt_key[(i+ByteOffset) % encrypt_key.Length] ^ temp;
                        *(uint*)ptr = temp;
                        ptr += 4;
                        if(DynamicKey)
                            encrypt_key[(i+ByteOffset) % encrypt_key.Length] += (temp2 * 0xFFAA6DF) + 0x897A68A;
                    }

                    switch (BytesLeft)
                    {
                        case 3:
                        {
                            ushort org = *(ushort*)ptr;
                            byte org2 = *(byte*)(ptr + 2);
                            *(short*)ptr ^= (short)encrypt_key[((BytesLeft * Loops) + ByteOffset) % encrypt_key.Length];
                            *(byte*)(ptr + 2) ^= (byte)encrypt_key[((BytesLeft * Loops) + ByteOffset) % encrypt_key.Length];
                            if(DynamicKey)
                            {
                                encrypt_key[((BytesLeft * Loops) + ByteOffset) % encrypt_key.Length] += (uint)((org * 0x56B5A67) + 0x5F74A4A0);
                                encrypt_key[((BytesLeft * Loops) + ByteOffset) % encrypt_key.Length] += (uint)((org2 * 0xA6B4A3A) + 0x7B96A78A);
                            }
                            break;
                        }
                        case 2:
                        {
                            uint org = *(ushort*)ptr;
                            *(short*)ptr ^= (short)encrypt_key[((BytesLeft * Loops) + ByteOffset) % encrypt_key.Length];
                            if(DynamicKey)
                                encrypt_key[((BytesLeft * Loops) + ByteOffset) % encrypt_key.Length] += (org * 0xBAD6A7A) + 0x78A7667B;
                            break;
                        }
                        case 1:
                        {
                            uint org = *(byte*)ptr;
                            *(byte*)ptr ^= (byte)encrypt_key[((BytesLeft * Loops) + ByteOffset) % encrypt_key.Length];
                            if(DynamicKey)
                                encrypt_key[((BytesLeft * Loops) + ByteOffset) % encrypt_key.Length] += (org * 0x76A867FF) + 0x7A668A8;
                            break;
                        }
                    }
                }
            }
            return data;
        }

        public byte[] Decrypt(byte[] data, int offset, int length)
        {
            lock (ProcessLock)
            {
                if (data.Length <= 0 || length + offset > data.Length)
                    return data;

                byte ByteOffset = 0;// (byte)DecRnd.Next(10, 255);

                fixed (byte* x = &(data[offset]))
                {
                    byte* ptr = x;
                    Int32 BytesLeft = length & 3;
                    Int32 Loops = length >> 2;
                    uint temp = 0;

                    for (int i = 0; i < Loops; i++)
                    {
                        uint temp2 = *(uint*)ptr;
                        *(uint*)ptr = temp2 ^ decrypt_key[(i+ByteOffset) % decrypt_key.Length] ^ temp;

                        if(DynamicKey)
                            decrypt_key[(i+ByteOffset) % decrypt_key.Length] += (*(uint*)ptr * 0xFFAA6DF) + 0x897A68A;

                        temp = temp2;
                        ptr += 4;
                    }

                    switch (BytesLeft)
                    {
                        case 3:
                        {
                            *(ushort*)ptr ^= (ushort)decrypt_key[((BytesLeft * Loops) + ByteOffset) % decrypt_key.Length];
                            *(byte*)(ptr + 2) ^= (byte)decrypt_key[((BytesLeft * Loops) + ByteOffset) % decrypt_key.Length];
                            if(DynamicKey)
                            {
                                decrypt_key[((BytesLeft * Loops) + ByteOffset) % decrypt_key.Length] += (uint)(*(ushort*)ptr * 0x56B5A67) + 0x5F74A4A0;
                                decrypt_key[((BytesLeft * Loops) + ByteOffset) % decrypt_key.Length] += (uint)(*(byte*)(ptr + 2) * 0xA6B4A3A) + 0x7B96A78A;
                            }
                            break;
                        }
                        case 2:
                        {
                            *(ushort*)ptr ^= (ushort)decrypt_key[((BytesLeft * Loops) + ByteOffset) % decrypt_key.Length];
                            if(DynamicKey)
                                decrypt_key[((BytesLeft * Loops) + ByteOffset) % decrypt_key.Length] += (uint)(*(ushort*)ptr * 0xBAD6A7A) + 0x78A7667B;
                            break;
                        }
                        case 1:
                        {
                            *(byte*)ptr ^= (byte)decrypt_key[((BytesLeft * Loops) + ByteOffset) % decrypt_key.Length];
                            if(DynamicKey)
                                decrypt_key[((BytesLeft * Loops) + ByteOffset) % decrypt_key.Length] += (uint)(*(byte*)ptr * 0x76A867FF) + 0x7A668A8;
                            break;
                        }
                    }
                }
            }
            return data;
        }
    }
}