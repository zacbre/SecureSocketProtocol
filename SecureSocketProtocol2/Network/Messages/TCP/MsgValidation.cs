using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages.TCP
{
    /// <summary>
    /// This message is being used in the HandShake
    /// </summary>
    internal class MsgValidation : IMessage
    {
        public byte[] ValidationKey;
        public bool ValidationSuccess;

        public MsgValidation()
            : base()
        {

        }

        public MsgValidation(byte[] ValidationKey)
            : base()
        {
            this.ValidationKey = ValidationKey;
        }
        public MsgValidation(bool ValidationSuccess)
            : base()
        {
            this.ValidationSuccess = ValidationSuccess;
        }
    }
}