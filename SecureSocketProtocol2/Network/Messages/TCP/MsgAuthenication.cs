using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages.TCP
{
    internal class MsgAuthenication : IMessage
    {
        public string Username;
        public string Password;
        public MsgAuthenication()
            : base()
        {

        }
        public MsgAuthenication(string Username, string Password)
            : base()
        {
            this.Username = Username;
            this.Password = Password;
        }
    }
}