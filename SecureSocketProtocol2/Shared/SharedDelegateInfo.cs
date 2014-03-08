using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Shared
{
    [Serializable]
    public class SharedDelegateInfo
    {
        public bool isUnchecked;
        public bool UseUDP;
        public bool UsePacketQueue;
        public bool NoWaitingTime;
    }
}