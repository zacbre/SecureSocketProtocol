using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages.TCP
{
    internal class MsgDummy : IMessage
    {
        /// <summary> Just empty data, will fool analysers when it's encrypted :) </summary>
        public byte[] Zeros = new byte[new Random().Next(0, 100)];

        public MsgDummy()
            : base()
        {

        }
    }
}