using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace SecureSocketProtocol2.Misc
{
    public class ProgressHelper
    {
        public ulong Speed { get; private set; }
        public ulong Maximum { get; private set; }
        public ulong Done { get; private set; }
        public TimeSpan RunTime { get { return new TimeSpan(sw.ElapsedTicks); } }
        public int Progress
        {
            get
            {
                if (Done == 0 || Maximum == 0)
                    return 0;
                return (int)Math.Round((float)Done / (float)Maximum * 100F, 0);
            }
        }

        public TimeSpan TimeLeft
        {
            get
            {
                int time = (int)((Maximum - Done) / (Speed > 0 ? Speed : 1));
                return TimeSpan.FromSeconds(time);
            }
        }

        private ulong _speed;
        private Stopwatch sw;

        public ProgressHelper(ulong MaximumSize)
        {
            this.Maximum = MaximumSize;
            this.sw = Stopwatch.StartNew();
        }

        public void Update(ulong UpdateCount)
        {
            if (UpdateCount + Done > Maximum)
                return;

            _speed += UpdateCount;
            Speed += UpdateCount;
            Done += UpdateCount;

            if (sw.ElapsedMilliseconds >= 1000)
            {
                Speed = _speed;
                _speed = 0;
                this.sw = Stopwatch.StartNew();
            }
        }
    }
}