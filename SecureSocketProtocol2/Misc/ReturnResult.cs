using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Misc
{
    [Serializable()]
    internal class ReturnResult
    {
        public object ReturnValue;
        public string exceptionMessage;
        public bool ExceptionOccured;

        public ReturnResult(object ReturnValue, bool ExceptionOccured, string exceptionMessage = "")
        {
            this.ReturnValue = ReturnValue;
            this.ExceptionOccured = ExceptionOccured;
            this.exceptionMessage = exceptionMessage;
        }
    }
}