using SecureSocketProtocol2.Network.RootSocket;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Interfaces.Shared
{
    public interface ISharedClientRoot
    {
        bool RequestPeerConnection(string VirtualIP, decimal ConnectionId);
        void NewPeerconnection(decimal ConnectionId);
    }
}