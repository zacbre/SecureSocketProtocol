using SecureSocketProtocol2.Attributes;
using SecureSocketProtocol2.Interfaces.Shared;
using SecureSocketProtocol2.Network.RootSocket;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Shared.SharedClasses
{
    public class SharedClientRoot : ISharedClientRoot
    {
        public SSPClient client;

        public SharedClientRoot(SSPClient client)
        {
            this.client = client;
        }

        [RemoteExecution(30000, false)]
        public bool RequestPeerConnection(string VirtualIP, decimal ConnectionId)
        {
            lock (client.PeerConnections)
            {
                RootPeer peer = client.onGetNewPeerObject();
                peer.VirtualIP = VirtualIP;
                peer.ConnectionId = ConnectionId;
                peer._client = client;
                peer.FromClient = client;

                if (client.PeerConnections.ContainsKey(ConnectionId))
                    client.Disconnect(); //should never happen!

                bool HasPermission = client.onPeerConnectionRequest(peer);

                if (HasPermission)
                {
                    client.PeerConnections.Add(ConnectionId, peer);
                }
                else
                {
                    peer = null;
                }
                return HasPermission;
            }
        }

        [UncheckedRemoteExecution]
        public void NewPeerconnection(decimal ConnectionId)
        {
            lock (client.PeerConnections)
            {
                if (client.PeerConnections.ContainsKey(ConnectionId))
                {
                    client.PeerConnections[ConnectionId].Connected = true;
                    client.PeerConnections[ConnectionId].onRegisterMessages(client.PeerConnections[ConnectionId].Client.MessageHandler);
                    client.PeerConnections[ConnectionId].onClientConnect();
                    client.PeerConnections[ConnectionId].InvokedOnConnect = true;
                }
            }
        }
    }
}