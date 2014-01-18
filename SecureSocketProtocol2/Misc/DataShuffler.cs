using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace SecureSocketProtocol2.Misc
{
    public class DataShuffler
    {
        public delegate void ShuffleStatusCallback(double Progress, TimeSpan TimeLeft, int speed);
        private Random ShuffleRnd;
        private Random UnshuffleRnd;

        public DataShuffler(int Seed)
        {
            this.ShuffleRnd = new Random(Seed);
            this.UnshuffleRnd = new Random(Seed);
        }

        /// <summary>
        /// Shuffle the data to randomized positions to make it harder to read
        /// </summary>
        /// <param name="data">The data you want to shuffle</param>
        /// <param name="ChunkSize">If data is smaller then ChunkSize it will use 1 byte instead of ChunkSize, Higher=Faster, ChunkSize at UnShuffle must be equal at this method</param>
        /// <returns>The shuffled data</returns>
        public T[] Shuffle<T>(T[] data, int ChunkSize = 255, ShuffleStatusCallback callback = null)
        {
            if (data.Length <= 1)
                return data;

            lock (ShuffleRnd)
            {
                T[] ShuffledData = new T[data.Length];
                List<DataShuffleInfo> NewPos = new List<DataShuffleInfo>();
                GetNewPos(ref NewPos, data, ref ShuffleRnd, ChunkSize, callback);

                for (int i = 0; i < NewPos.Count; i++)
                {
                    if (NewPos[i].Length == 1)
                    {
                        ShuffledData[NewPos[i].NewIndex] = data[NewPos[i].OldIndex];
                    }
                    else
                    {
                        Buffer.BlockCopy(data, NewPos[i].OldIndex, ShuffledData, NewPos[i].NewIndex, NewPos[i].Length);
                    }
                }
                NewPos.Clear();
                return ShuffledData;
            }
        }

        /// <summary>
        /// UnShuffle the data that has been shuffled
        /// </summary>
        /// <param name="data">The shuffled data</param>
        /// <returns>The UnShuffled data</returns>
        public T[] UnShuffle<T>(T[] data, int ChunkSize = 255, ShuffleStatusCallback callback = null)
        {
            if (data.Length <= 1)
                return data;

            lock (UnshuffleRnd)
            {
                T[] UnShuffledData = new T[data.Length];
                List<DataShuffleInfo> NewPos = new List<DataShuffleInfo>();
                GetNewPos(ref NewPos, data, ref UnshuffleRnd, ChunkSize, callback);

                for (int i = 0; i < NewPos.Count; i++)
                {
                    if (NewPos[i].Length == 1)
                    {
                        UnShuffledData[NewPos[i].OldIndex] = data[NewPos[i].NewIndex];
                    }
                    else
                    {
                        Buffer.BlockCopy(data, NewPos[i].NewIndex, UnShuffledData, NewPos[i].OldIndex, NewPos[i].Length);
                    }
                }
                NewPos.Clear();
                return UnShuffledData;
            }
        }

        private void GetNewPos<T>(ref List<DataShuffleInfo> NewPos, T[] data, ref Random rnd, int ChunkSize, ShuffleStatusCallback callback)
        {
            lock (rnd)
            {
                bool isOneByte = ChunkSize >= data.Length;
                int size = isOneByte ? 1 : ChunkSize;
                int MaxSize = (int)Math.Floor((float)data.Length / (float)size);
                int BytesLeft = data.Length - (size * MaxSize);
                int BytesLeftIndex = -1;
                int[] Indexes = new int[MaxSize];
                ProgressHelper progressHelper = new ProgressHelper((ulong)MaxSize);

                //lets pre-generate the indexes

                for (int i = 0; i < Indexes.Length; i++)
                    Indexes[i] = i;

                int prevProgress = 0;
                for (int i = Indexes.Length, j = 0; i > 1; i--, j++)
                {
                    int pos = rnd.Next(i); // 0 <= j <= i-1
                    int tmp = Indexes[pos];
                    Indexes[pos] = Indexes[i - 1];
                    Indexes[i - 1] = tmp;

                    progressHelper.Update(1);

                    if (callback != null)
                    {
                        double progress = progressHelper.Progress;
                        if (prevProgress != progress)
                        {
                            callback(progress, progressHelper.TimeLeft, (int)progressHelper.Speed);
                            prevProgress = progressHelper.Progress;
                        }
                    }
                }

                /*for (int i = 0; i < MaxSize; i++)
                {
                    decimal tmp = rnd.NextDecimal();
                    while (Indexes.ContainsKey(tmp))
                        tmp = rnd.NextDecimal();
                    Indexes.Add(tmp, i);
                }*/

                //lets generate where the data needs to be
                for (int i = 0, j = 0; i < data.Length; i += size, j++)
                {
                    if (i + size > data.Length)
                    {
                        BytesLeftIndex = i;
                        break;
                    }

                    DataShuffleInfo inf = new DataShuffleInfo()
                    {
                        OldIndex = i,
                        NewIndex = Indexes[j] * size,
                        Length = size
                    };

                    if (inf.OldIndex + size > data.Length)
                        inf.Length = (inf.OldIndex + size) - data.Length;
                    if (inf.NewIndex + size > data.Length)
                        inf.Length = (inf.NewIndex + size) - data.Length;

                    NewPos.Add(inf);
                }

                if (BytesLeft > 0 && BytesLeftIndex >= 0)
                {
                    //need some improvement
                    NewPos.Add(new DataShuffleInfo() { OldIndex = BytesLeftIndex, NewIndex = BytesLeftIndex, Length = BytesLeft });
                }
                Indexes = null;
            }
        }
        public class DataShuffleInfo
        {
            public int OldIndex;
            public int Length;
            public int NewIndex;
        }
    }
}