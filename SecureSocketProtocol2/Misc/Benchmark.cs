using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace SecureSocketProtocol2.Misc
{
    public delegate void BenchCallback();
    public class Benchmark
    {
        public ulong SpeedPerSec { get; private set; }
        private Stopwatch SW;
        private ulong speed = 0;
        public bool PastASecond { get; private set; }

        public Benchmark()
        {

        }

        public void Bench(BenchCallback callback)
        {
            PastASecond = false;
            if (SW == null)
                SW = Stopwatch.StartNew();

            callback();
            speed++;

            if (SW.ElapsedMilliseconds >= 1000)
            {
                SpeedPerSec = speed;
                speed = 0;
                SW = Stopwatch.StartNew();
                PastASecond = true;
            }
        }
    }
}
