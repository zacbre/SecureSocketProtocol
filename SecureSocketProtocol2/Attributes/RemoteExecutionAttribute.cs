using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Attributes
{
    /// <summary>
    /// Improves security of Shared Classes
    /// </summary>
    public class RemoteExecutionAttribute : Attribute
    {
        public uint TimeOut { get; private set; }
        public object TimeOutValue { get; private set; }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="TimeOut">When 0 it will keep waiting for a value, if >=1 it could give a time out</param>
        /// <param name="TimeOutValue">The value to give at time out</param>
        public RemoteExecutionAttribute(uint TimeOut, object TimeOutValue)
            : base()
        {
            this.TimeOut = TimeOut;
            this.TimeOutValue = TimeOutValue;
        }
    }
}