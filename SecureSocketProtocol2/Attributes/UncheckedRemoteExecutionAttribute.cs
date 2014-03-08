using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Attributes
{
    /// <summary>
    /// Improves security of Shared Classes, preventing exploits<br/>
    /// Unchecked only works for the return type VOID so it doesn't wait till the method is totally executed
    /// </summary>
    public class UncheckedRemoteExecutionAttribute : Attribute
    {
        public UncheckedRemoteExecutionAttribute()
            : base()
        {

        }
    }
}
