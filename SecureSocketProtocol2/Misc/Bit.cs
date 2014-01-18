using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Misc
{
    public class Bit
    {
        private bool[] data;

        /// <summary> Initialize 8 bits of data </summary>
        public Bit()
        {
            data = new bool[8];
        }

        /// <summary> Initialize 8 bits with data </summary>
        public Bit(byte Data)
            : this()
        {
            byte Multiplier = 1;
            for (int i = 0; i < this.data.Length; i++)
            {
                data[i] = (Data & Multiplier) > 0;
                Multiplier *= 2;
            }
        }

        public void SetIndex(int index, bool ZeroOne)
        {
            data[index] = ZeroOne;
        }

        public bool GetIndex(int index)
        {
            return data[index];
        }

        public byte ToByte()
        {
            byte ret = 0;
            byte Multiplier = 1;

            for (int i = 0; i < data.Length; i++)
            {
                if (data[i])
                    ret += Multiplier;
                Multiplier *= 2;
            }
            return ret;
        }
    }
}