using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Attributes
{
    /// <summary>
    /// This attribute will show the method to use UDP instead of TCP
    /// This only works for the return type VOID so it doesn't wait till the method is totally executed
    /// </summary>
    public class UdpMethodAttribute : Attribute
    {
        public UdpMethodAttribute()
            : base()
        {

        }
    }
}
