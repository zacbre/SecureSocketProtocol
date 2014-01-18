using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network
{
    public abstract class DPIRule
    {
        public abstract bool Inspect(byte[] data);
    }
}