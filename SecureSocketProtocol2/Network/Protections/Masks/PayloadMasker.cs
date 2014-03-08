using SecureSocketProtocol2.Interfaces;
using SecureSocketProtocol2.Misc;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace SecureSocketProtocol2.Network.Protections.Masks
{
    public class PayloadMasker : IProtection
    {
        public override ProtectionType Type
        {
            get { return ProtectionType.Masker; }
        }

        private SortedList<decimal, decimal> DigitsTable; //temp
        private Stream DataTableStream;
        private int ByteLength = 0;
        private List<int> startPositions = new List<int>(new int[] { 0, 1280, 327680 });
        public int StartPosition_1 { get { return startPositions[0]; } }
        public int StartPosition_2 { get { return startPositions[1]; } }
        public int StartPosition_3 { get { return startPositions[2]; } }

        /// <summary>
        /// The Payload Masker is a security layer for masking the payload 
        /// The masker will swap the original byte(s) with the mask data you generated
        /// </summary>
        /// <param name="DataTableStream"></param>
        public PayloadMasker(Stream DataTableStream)
            : base()
        {
            this.DataTableStream = DataTableStream;

            //check the max byte length

            for (int i = 0; i < startPositions.Count; i++)
            {
                if (startPositions[i] < DataTableStream.Length)
                    ByteLength++;
                else
                    break;
            }            

            /*List<decimal> Table = new List<decimal>();
            while (DataTableStream.Position < DataTableStream.Length)
            {
                byte length = (byte)DataTableStream.ReadByte();

                if (length > ByteLength)
                    ByteLength = length;

                byte[] Digits = new byte[4];
                if (length >= 1 || length <= 3) //play it safe
                {
                    DataTableStream.Read(Digits, 0, Digits.Length);
                    PayloadReader reader = new PayloadReader(Digits);
                    uint target = reader.ReadUInteger();
                    Table.Add(target);
                }
                else
                {
                    Digits = new byte[16];
                    DataTableStream.Read(Digits, 0, Digits.Length);
                    PayloadReader reader = new PayloadReader(Digits);
                    decimal target = reader.ReadDecimal();
                    Table.Add(target);
                }
            }

            //setup the DigitsTable
            this.DigitsTable = new SortedList<decimal, decimal>();
            for (int i = 0; i < Table.Count; i++)
            {
                DigitsTable.Add(Table[i], i);
            }*/
        }

        private bool GetOffset(int ByteOffset, decimal source, ref decimal Target)
        {
            switch (ByteOffset)
            {
                case 1:
                case 2:
                case 3:
                {
                    int startPos = startPositions[ByteOffset - 1];

                    /*if (ByteOffset == 2)
                        startPos += ((int)source - 0) * 4;
                    if (ByteOffset == 3)
                        startPos += ((int)source - 65535) * 4;
                    if (ByteOffset == 4)
                        startPos += ((int)source - 16777215) * 4;*/

                    DataTableStream.Position = startPos;
                    int ByteLength = DataTableStream.ReadByte();
                    
                    byte[] Digits = new byte[4];
                    DataTableStream.Read(Digits, 0, Digits.Length);
                    PayloadReader reader = new PayloadReader(Digits);
                    uint target = reader.ReadUInteger();

                    while (false)
                    {
                        ByteLength = DataTableStream.ReadByte();
                        DataTableStream.Position += 4;
                    }
                    return true;
                }
                default:
                {

                    break;
                }
            }

            return false;
        }

        public override byte[] Encode(ref byte[] data, ref uint offset, ref uint length, ref PacketHeader packetHeader)
        {
            MemoryStream masked = new MemoryStream(data.Length);

            uint blocks = (uint)(length / ByteLength);
            uint DataLeft = (uint)(length % ByteLength);

            for (int i = 0, j = 0; i < blocks; i++, j += ByteLength)
            {
                byte[] newData = GetNewData(true, data, j);
                masked.Write(newData, 0, newData.Length);
            }
            data = masked.GetBuffer();
            return data;
        }

        public override byte[] Decode(ref byte[] data, ref uint offset, ref uint length, ref PacketHeader packetHeader)
        {
            MemoryStream masked = new MemoryStream(data.Length);

            uint blocks = (uint)(length / ByteLength);
            uint DataLeft = (uint)(length % ByteLength);

            for (int i = 0, j = 0; i < blocks; i++, j += ByteLength)
            {
                byte[] newData = GetNewData(false, data, j);
                masked.Write(newData, 0, newData.Length);
            }
            data = masked.GetBuffer();
            return data;
        }

        private byte[] GetNewData(bool IsShuffle, byte[] data, int offset)
        {
            decimal val = 0;

            if (ByteLength == 1)
                val = data[offset];
            else if (ByteLength == 2)
                val = BitConverter.ToUInt16(data, offset);
            else if (ByteLength == 3)
                val = (int)data[offset] | data[offset + 1] << 8 | data[offset + 2] << 16;
            else if (ByteLength == 4)
                val = BitConverter.ToUInt32(data, offset);
            else if (ByteLength == 8)
                val = BitConverter.ToUInt64(data, offset);

            decimal NewVal = 0;

            if (IsShuffle)
            {
                int index = 0; //DigitsTable.FindIndex(new Predicate<decimal>((decimal target) => target == val));

                decimal Target = 0;
                if (!GetOffset(ByteLength, val, ref Target))
                    throw new Exception("Failed to retrieve the Mask Information, corrupted data?");
                NewVal = index;
            }
            else
            {


                /*if (val < DigitsTable.Count)
                {
                    NewVal = DigitsTable[(int)val];
                }
                else
                {
                    throw new Exception("Failed to retrieve the Mask Information, corrupted data?");
                }
                NewVal = DigitsTable[(int)val];*/
            }

            if (ByteLength == 1)
                return new byte[] { data[offset] };
            else if (ByteLength == 2)
                return BitConverter.GetBytes((ushort)NewVal);
            else if(ByteLength == 3)
                return new byte[] { (byte)NewVal, (byte)((int)NewVal >> 8), (byte)((int)NewVal >> 16) };
            else if (ByteLength == 4)
                return BitConverter.GetBytes((uint)NewVal);
            else if (ByteLength == 8)
                return BitConverter.GetBytes((ulong)NewVal);
            return new byte[0];
        }

        /// <summary>
        /// Create the Mask Table the PayloadMasker will use
        /// </summary>
        /// <param name="Seed">The seed will be used to randomize the start position</param>
        /// <param name="MaxLength">The maximum length in bytes to bruteforce</param>
        /// <param name="OutStream">The stream for writing the output</param>
        public static void CreateMaskTable(int Seed, ushort MaxLength, Stream OutStream)
        {
            if (!OutStream.CanWrite)
                throw new Exception("OutStream does not have Write");
            if (MaxLength <= 0)
                throw new Exception("MaxLength should be atleast 1 or higher");

            Stopwatch sw = Stopwatch.StartNew();
            ulong Speed = 0;
            double PrevVal = 0;
            double MaxVal = 0;
            List<double> Digits = new List<double>();
            DataShuffler dataShuffler = new DataShuffler(Seed);

            for (double i = 0, h = 8; i < MaxLength; i++, h += 8)
            {
                int ByteIndex = (int)i + 1;
                PrevVal = MaxVal;
                MaxVal = Math.Pow(2, h);
                ProgressHelper progressHelper = new ProgressHelper((ulong)(MaxVal - PrevVal));

                for (double j = PrevVal; j < MaxVal; j++)
                {
                    byte[] num = BitConverter.GetBytes((ulong)j);
                    Speed++;
                    Digits.Add(j);
                    progressHelper.Update(1);

                    if(Digits.Count > 10000000)
                        SaveMaskTable(ref Digits, ref dataShuffler, ByteIndex, ref OutStream);

                    if (sw.ElapsedMilliseconds >= 1000)
                    {
                        Console.WriteLine(num[0].ToString("X4") + " " +
                                          num[1].ToString("X4") + " " +
                                          num[2].ToString("X4") + " " +
                                          num[3].ToString("X4") + " " +
                                          num[4].ToString("X4") + " " +
                                          num[5].ToString("X4") + " " +
                                          num[6].ToString("X4") + " " +
                                          num[7].ToString("X4"));
                        TimeSpan ETA = progressHelper.TimeLeft;
                        Console.WriteLine("Speed " + Speed + " a second, current byte length: " + ByteIndex + ", " + progressHelper.Progress + "% done, Time Left:" + ETA.Hours.ToString("D2") + ":" + ETA.Minutes.ToString("D2") + ":" + ETA.Seconds.ToString("D2"));
                        Speed = 0;
                        sw = Stopwatch.StartNew();
                    }
                }
                SaveMaskTable(ref Digits, ref dataShuffler, ByteIndex, ref OutStream);
            }
        }
        private static void SaveMaskTable(ref List<double> Digits, ref DataShuffler dataShuffler, int ByteIndex, ref Stream OutStream)
        {
            if (Digits.Count == 0)
                return;

            Console.WriteLine("Digits:" + Digits.Count);
            PayloadWriter pw = new PayloadWriter();

            double[] Shuffled = dataShuffler.Shuffle<double>(Digits.ToArray(), 1, (double progress, TimeSpan TimeLeft, int speed) =>
            {
                if((int)progress % 5 == 0.0F)
                {
                    Console.WriteLine("Shuffle progress:" + progress + ", Speed: " + speed + ", Time Left: " + TimeLeft.Hours.ToString("D2") + ":" + TimeLeft.Minutes.ToString("D2") + ":" + TimeLeft.Seconds.ToString("D2"));
                }
            });

            for (int k = 0; k < Shuffled.Length; k++)
            {
                int Target = (int)Shuffled[k];

                pw.WriteByte((byte)ByteIndex); //byte length

                if (ByteIndex >= 1 || ByteIndex <= 3) //play it safe
                {
                    pw.WriteUInteger((uint)Target);
                }
                else
                {
                    pw.WriteDecimal(Target);
                }

                if (pw.Length >= 65535)
                {
                    OutStream.Write(pw.GetBuffer(), 0, pw.Length);
                    OutStream.Flush();
                    pw = new PayloadWriter();
                }
            }
            if (pw.Length > 0)
            {
                OutStream.Write(pw.GetBuffer(), 0, pw.Length);
                OutStream.Flush();
            }
            pw.Dispose();
            Digits.Clear();
        }

        public override void onApplyPrivateKey(byte[] PrivateKey)
        {

        }
    }
}