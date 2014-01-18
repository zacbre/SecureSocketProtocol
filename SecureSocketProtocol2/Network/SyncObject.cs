using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Threading;

namespace SecureSocketProtocol2.Network
{
    public sealed class SyncObject
    {
        /// <summary> Is the object being pulsed by a other thread </summary>
        public bool Pulsed { get; internal set; }
        private Object LockedObject = new Object();

        /// <summary> The main object </summary>
        public Object Value = null;
        public bool TimedOut = false;
        private Connection connection;

        public SyncObject(Connection connection)
        {
            this.connection = connection;
        }

        /// <param name="TimeOut">The time to wait for the object being pulsed</param>
        public T Wait<T>(T TimeOutValue, uint TimeOut = 0)
        {
            TimeOut = 0;
            if (Pulsed)
                return (T)Value;

            Stopwatch waitTime = Stopwatch.StartNew();

            lock (LockedObject)
            {
                while (!Pulsed && connection.Connected)
                {
                    if (TimeOut == 0)
                    {
                        Monitor.Wait(LockedObject, 250);
                    }
                    else
                    {
                        //Monitor.Wait(LockedObject, (int)TimeOut);
                        Monitor.Wait(LockedObject, 250);
                        this.TimedOut = waitTime.ElapsedMilliseconds >= TimeOut;

                        if (this.TimedOut)
                            return (T)TimeOutValue;
                    }
                }

                if (!Pulsed)
                    return TimeOutValue;
            }
            return (T)Value;
        }

        public void Pulse()
        {
            lock (LockedObject)
            {
                Monitor.Pulse(LockedObject);
            }
            Pulsed = true;
        }
    }
}