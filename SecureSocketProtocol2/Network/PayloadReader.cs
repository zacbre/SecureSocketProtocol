using SecureSocketProtocol2.Misc;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace SecureSocketProtocol2.Network
{
    public class PayloadReader : IDisposable
    {
        private byte[] _Packet;
        private int _Offset;
        public PayloadReader(byte[] packet)
        {
            _Packet = packet;
            _Offset = 0;
        }

        public int Offset
        {
            get { return _Offset; }
            set { _Offset = value; }
        }

        public int ReadInteger()
        {
            int result = BitConverter.ToInt32(_Packet, _Offset);
            _Offset += 4;
            return result;
        }
        public float ReadFloat()
        {
            float result = BitConverter.ToSingle(_Packet, _Offset);
            _Offset += 4;
            return result;
        }

        /// <summary>
        /// A integer with 3 bytes not 4
        /// </summary>
        public int ReadThreeByteInteger()
        {
            return (int)ReadByte() | ReadByte() << 8 | ReadByte() << 16;
        }

        public uint ReadUInteger()
        {
            uint result = BitConverter.ToUInt32(_Packet, _Offset);
            _Offset += 4;
            return result;
        }

        public byte ReadByte()
        {
            byte result = _Packet[_Offset];
            _Offset += 1;
            return result;
        }

        public bool ReadBool()
        {
            return ReadByte() >= 1;
        }

        public byte[] ReadBytes(int Length)
        {
            byte[] result = new byte[Length];
            Array.Copy(_Packet, _Offset, result, 0, Length);
            _Offset += Length;
            return result;
        }

        public short ReadShort()
        {
            short result = BitConverter.ToInt16(_Packet, _Offset);
            _Offset += 2;
            return result;
        }
        public ushort ReadUShort()
        {
            ushort result = BitConverter.ToUInt16(_Packet, _Offset);
            _Offset += 2;
            return result;
        }

        public double ReadDouble()
        {
            double result = BitConverter.ToDouble(_Packet, _Offset);
            _Offset += 8;
            return result;
        }

        public long ReadLong()
        {
            long result = BitConverter.ToInt64(_Packet, _Offset);
            _Offset += 8;
            return result;
        }

        public ulong ReadULong()
        {
            ulong result = BitConverter.ToUInt64(_Packet, _Offset);
            _Offset += 8;
            return result;
        }

        public decimal ReadDecimal()
        {
            using (MemoryStream stream = new MemoryStream(_Packet, _Offset,  16))
            {
                using (BinaryReader reader = new BinaryReader(stream))
                {
                    _Offset += 16;
                    return reader.ReadDecimal();
                }
            }
        }

        public string ReadString()
        {
            string result = "";
            try
            {
                result = System.Text.Encoding.Unicode.GetString(_Packet, _Offset, _Packet.Length - _Offset);
                int idx = result.IndexOf((char)0x00);
                if (!(idx == -1))
                    result = result.Substring(0, idx);
                _Offset += (result.Length * 2) + 2;
            }
            catch (Exception ex)
            {
                throw new Exception(ex.StackTrace + "\r\n" + ex.Message);
            }
            return result;
        }

        public object ReadObject()
        {
            SmartSerializer serializer = new SmartSerializer();
            return serializer.Deserialize(ReadBytes(ReadInteger()));
        }

        public T ReadObject<T>()
        {
            return (T)ReadObject();
        }

        public BigInteger ReadBigInteger()
        {
            int length = ReadByte();
            return new BigInteger(ReadBytes(length));
        }

        public byte[] Packet
        {
            get { return _Packet; }
        }

        public void Dispose()
        {
            _Packet = null;
            _Offset = -1;
        }
    }
}