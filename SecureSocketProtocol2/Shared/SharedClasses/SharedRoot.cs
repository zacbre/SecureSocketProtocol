using SecureSocketProtocol2.Attributes;
using SecureSocketProtocol2.Interfaces.Shared;
using SecureSocketProtocol2.Misc;
using SecureSocketProtocol2.Network.RootSocket;
using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace SecureSocketProtocol2.Shared.SharedClasses
{
    internal class SharedRoot : ISharedRoot
    {
        public SSPClient client;
        public SharedRoot(SSPClient client)
        {
            this.client = client;
        }

        [RemoteExecution(30000, "")]
        public string ResolveDns(string DnsName)
        {
            RootDnsInfo info = client.Server.RootSocket_DNS.GetDnsRecord(DnsName);
            if (info != null)
                return info.VirtualIp;
            return "";
        }

        [RemoteExecution(30000, false)]
        public DnsErrorCode RegisterDns(string DnsName)
        {
            if (DnsName.Length > 100)
                return DnsErrorCode.DomainNameIsTooLong;

            DnsName = DnsName.ToLower();

            if (client.Server.onPeerCreateDnsRequest(DnsName, client))
            {
                uint DnsId = 0;
                return client.Server.RootSocket_DNS.ApplyDnsName(DnsName, ref DnsId, client) ? DnsErrorCode.Success : DnsErrorCode.DnsAlreadyRegistered;
            }
            return DnsErrorCode.PermissionDenied;
        }

        [RemoteExecution(0, null)]
        public PeerResponse ConnectToPeer(string VirtualIpOrDns)
        {
            SSPClient TargetClient = null;

            //check if dns name
            if (!Regex.IsMatch(VirtualIpOrDns, RootPeer.IpValidationString))
            {
                RootDnsInfo inf = client.Server.RootSocket_DNS.GetDnsRecord(VirtualIpOrDns);
                if (inf != null)
                    VirtualIpOrDns = inf.VirtualIp;
            }

            TargetClient = client.Server.GetClient(VirtualIpOrDns);

            if (TargetClient == null)
            {
                return new PeerResponse(PeerErrorCode.PeerNotFound, 0, "");
            }

            //check if server side allows this connection
            if (!client.Server.onPeerConnectionRequest(client, TargetClient))
                return new PeerResponse(PeerErrorCode.PermissionDenied, 0, "");

            //check if target client allows this connection
            decimal ConnectionId = 0;
            bool HasPermission = false;

            lock (TargetClient.PeerConnections)
            {
                lock (client.PeerConnections)
                {
                    RandomDecimal rnd = new RandomDecimal(DateTime.Now.Millisecond);
                    ConnectionId = rnd.NextDecimal();
                    while (TargetClient.PeerConnections.ContainsKey(ConnectionId) || client.PeerConnections.ContainsKey(ConnectionId))
                        ConnectionId = rnd.NextDecimal();

                    try
                    {
                        HasPermission = TargetClient.SharedClientRoot.RequestPeerConnection(client.VirtualIP, ConnectionId);
                    }
                    catch { HasPermission = false; }

                    if (HasPermission)
                    {
                        RootPeer TargetPeer = client.onGetNewPeerObject();
                        TargetPeer._client = TargetClient;
                        TargetPeer.FromClient = TargetClient;
                        TargetPeer.ToClient = client;
                        TargetPeer.VirtualIP = client.VirtualIP;
                        TargetPeer.Connected = true;
                        TargetPeer.ConnectionId = ConnectionId;

                        RootPeer FromPeer = client.onGetNewPeerObject();
                        FromPeer._client = client;
                        FromPeer.FromClient = client;
                        FromPeer.ToClient = TargetClient;
                        FromPeer.VirtualIP = TargetClient.VirtualIP;
                        FromPeer.Connected = true;
                        FromPeer.ConnectionId = ConnectionId;

                        if(!TargetClient.PeerConnections.ContainsKey(ConnectionId))
                            TargetClient.PeerConnections.Add(ConnectionId, TargetPeer);

                        if (!client.PeerConnections.ContainsKey(ConnectionId))
                            client.PeerConnections.Add(ConnectionId, FromPeer);

                        TargetClient.SharedClientRoot.NewPeerconnection(ConnectionId);

                        return new PeerResponse(PeerErrorCode.Success, ConnectionId, TargetClient.VirtualIP);
                    }
                    return new PeerResponse(PeerErrorCode.PermissionDenied, 0, "");
                }
            }
        }
    }
}