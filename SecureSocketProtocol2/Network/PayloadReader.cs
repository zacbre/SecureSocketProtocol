using SecureSocketProtocol2.Misc;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace SecureSocketProtocol2.Network
{
    public class PayloadReader : IDisposable
    {
        private MemoryStream stream;
        public PayloadReader(byte[] packet)
        {
            stream = new MemoryStream(packet, 0, packet.Length, false, true);
        }

        public int Offset
        {
            get { return (int)stream.Position; }
            set { stream.Position = (int)value; }
        }

        public int ReadInteger()
        {
            return BitConverter.ToInt32(ReadBytes(4), 0);
        }
        public float ReadFloat()
        {
            return BitConverter.ToSingle(ReadBytes(4), 0);
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
            return BitConverter.ToUInt32(ReadBytes(4), 0);
        }

        public byte ReadByte()
        {
            return ReadBytes(1)[0];
        }

        public bool ReadBool()
        {
            return ReadByte() >= 1;
        }

        public byte[] ReadBytes(int Length)
        {
            byte[] result = new byte[Length];
            stream.Read(result, 0, result.Length);
            return result;
        }

        public short ReadShort()
        {
            short result = BitConverter.ToInt16(ReadBytes(2), 0);
            return result;
        }
        public ushort ReadUShort()
        {
            ushort result = BitConverter.ToUInt16(ReadBytes(2), 0);
            return result;
        }

        public double ReadDouble()
        {
            double result = BitConverter.ToDouble(ReadBytes(8), 0);
            return result;
        }

        public long ReadLong()
        {
            long result = BitConverter.ToInt64(ReadBytes(8), 0);
            return result;
        }

        public ulong ReadULong()
        {
            ulong result = BitConverter.ToUInt64(ReadBytes(8), 0);
            return result;
        }

        public decimal ReadDecimal()
        {
            using (BinaryReader reader = new BinaryReader(stream))
            {
                return reader.ReadDecimal();
            }
        }

        public string ReadString()
        {
            string result = "";
            try
            {
                result = System.Text.Encoding.Unicode.GetString(Buffer, Offset, (int)stream.Length - Offset);
                int idx = result.IndexOf((char)0x00);
                if (!(idx == -1))
                    result = result.Substring(0, idx);
                Offset += (result.Length * 2) + 2;
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

        public int Length
        {
            get { return (int)stream.Length; }
        }

        public byte[] Buffer
        {
            get { return this.stream.GetBuffer(); }
        }

        public void Dispose()
        {
            stream.Dispose();
        }
    }
}