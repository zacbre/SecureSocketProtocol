using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages.TCP.Handshake
{
    internal class MsgAuthentication : IMessage
    {
        public string Username;
        public string Password;
        public MsgAuthentication()
            : base()
        {

        }
        public MsgAuthentication(string Username, string Password)
            : base()
        {
            this.Username = Username;
            this.Password = Password;
        }
    }
}