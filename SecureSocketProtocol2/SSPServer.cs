using SecureSocketProtocol2.Interfaces.Shared;
using SecureSocketProtocol2.Misc;
using SecureSocketProtocol2.Network;
using SecureSocketProtocol2.Network.RootSocket;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace SecureSocketProtocol2
{
    public abstract class SSPServer : IDisposable
    {
        public abstract void onConnectionAccept(SSPClient client);
        public abstract void onConnectionClosed(SSPClient client);
        public abstract void onException(Exception ex);
        public abstract bool onAuthentication(SSPClient client, string Username, string Password);
        public abstract bool onPeerConnectionRequest(SSPClient FromClient, SSPClient ToClient);
        public abstract bool onPeerCreateDnsRequest(string DnsName, SSPClient Requestor);

        internal object AuthLock = new object();
        internal Socket TcpServer;
        internal Socket UdpServer;
        private SocketAsyncEventArgs udpAsyncSocket;
        public ServerProperties serverProperties { get; private set; }
        private Type baseClient;
        internal SortedList<decimal, SSPClient> Clients { get; private set; }
        private bool Running = false;
        internal PrivateKeyHandler KeyHandler;

        public RootDns RootSocket_DNS { get; private set; }
        internal RandomDecimal Random { get; private set; }

        /// <summary>
        /// Initialize a new SSPServer
        /// </summary>
        /// <param name="serverProperties">The properties for the server</param>
        public SSPServer(ServerProperties serverProperties)
        {
            if (serverProperties == null)
                throw new ArgumentNullException("serverProperties");

            this.Random = new RandomDecimal(DateTime.Now.Millisecond);
            this.KeyHandler = new PrivateKeyHandler(serverProperties.GenerateKeysInBackground);
            this.serverProperties = serverProperties;
            this.Clients = new SortedList<decimal, SSPClient>();
            this.TcpServer = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            this.TcpServer.Bind(new IPEndPoint(IPAddress.Parse(serverProperties.ListenIp), serverProperties.ListenPort));
            this.TcpServer.Listen(100);

            if (serverProperties.AllowUdp)
            {
                try
                {
                    this.UdpServer = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                    this.UdpServer.Bind(new IPEndPoint(IPAddress.Parse(serverProperties.ListenIp), serverProperties.ListenPort));
                    this.UdpServer.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.PacketInformation, true);
                    this.udpAsyncSocket = new SocketAsyncEventArgs();
                    this.udpAsyncSocket.SetBuffer(new byte[70000], 0, 70000);
                    this.udpAsyncSocket.RemoteEndPoint = new IPEndPoint(0, 0);
                    this.udpAsyncSocket.Completed += UdpAsyncSocketCallback;

                    if (!UdpServer.ReceiveFromAsync(udpAsyncSocket))
                        UdpAsyncSocketCallback(null, udpAsyncSocket);
                }
                catch(Exception ex)
                {
                    this.TcpServer.Close();
                    throw ex;
                }
            }

            this.RootSocket_DNS = new RootDns();

            //ThreadPool.QueueUserWorkItem(ServerThread);
            this.Running = true;

            TcpServer.BeginAccept(AsyncAction, null);
        }

        int tempId = 0;
        private void AsyncAction(IAsyncResult result)
        {
            Socket AcceptedSocket = null;
            try
            {
                AcceptedSocket = TcpServer.EndAccept(result);
            }
            catch { TcpServer.BeginAccept(AsyncAction, null); }

            //keep receiving connections
            SSPClient client = serverProperties.GetNewClient();
            client.Handle = AcceptedSocket;
            client.Connection = new Connection(client);
            client.RemoteIp = ((IPEndPoint)AcceptedSocket.RemoteEndPoint).Address.ToString();
            client.Connection.ClientId = Random.NextDecimal();//new Random(DateTime.Now.Millisecond).Next(0, 1000); //tempId++;//
            client.ServerAllowsReconnecting = client.ReconnectAtDisconnect;
            client.Server = this;
            client.Connection.State = ConnectionState.Open;

            lock(Clients)
            {
                while(Clients.ContainsKey(client.ClientId))
                    client.Connection.ClientId = Random.NextDecimal();
                Clients.Add(client.ClientId, client);
            }

            //accept new client
            TcpServer.BeginAccept(AsyncAction, null);

            try
            {
                if (!client.ServerHandshake(serverProperties, this.UdpServer, GetClients, KeyHandler))
                {
                    lock (Clients)
                    {
                        if (Clients.ContainsKey(client.ClientId))
                            Clients.Remove(client.ClientId);
                    }
                    client.Disconnect(DisconnectReason.HandShakeFailed);
                    return;
                }
            }
            catch(Exception ex)
            {
                onException(ex);
                client.Disconnect(DisconnectReason.HandShakeFailed);
                return;
            }

            try
            {
                client.onShareClasses();
            }
            catch (Exception ex)
            {
                client.onException(ex, ErrorType.UserLand);
            }

            client.StartReceiver();

            try
            {
                client.SharedClientRoot = client.GetSharedClass<ISharedClientRoot>("ROOTSOCKET_CLIENT");
            }
            catch(Exception ex)
            {
                //the shared class must exist
                client.Disconnect();
                return;
            }

            if (client.State != ConnectionState.Reconnecting)
            {
                client.onClientConnect();
            }
            onConnectionAccept(client);
        }

        /// <summary>
        /// This method is used to receive data from anyone
        /// The main function of this method is establishing udp-hole connections
        /// </summary>
        private void UdpAsyncSocketCallback(object o, SocketAsyncEventArgs e)
        {
            if (e.LastOperation == SocketAsyncOperation.ReceiveFrom)
            {
                try
                {
                    if (e.BytesTransferred >= 21)
                    {
                        PayloadReader pr = new PayloadReader(e.Buffer);
                        decimal ClientId = pr.ReadDecimal();

                        lock (Clients)
                        {
                            if (Clients.ContainsKey(ClientId))
                            {
                                SSPClient client = Clients[ClientId];
                                client.AsyncSocketCallback(o, e);
                            }
                        }
                    }
                }
                catch { }

                if (!UdpServer.ReceiveFromAsync(udpAsyncSocket))
                {
                    UdpAsyncSocketCallback(null, udpAsyncSocket);
                }
            }
        }

        public SSPClient[] GetClients()
        {
            lock (Clients)
            {
                SSPClient[] c = new SSPClient[Clients.Count];
                Clients.Values.CopyTo(c, 0);
                return c;
            }
        }

        internal string GetNewVirtualIp()
        {
            lock(Clients)
            {
                Random rnd = new Random(DateTime.Now.Millisecond);
                string VirtualIp = rnd.Next(1, 255) + "." + rnd.Next(1, 255) + "." + rnd.Next(1, 255) + "." + rnd.Next(1, 255);

                while(GetClient(VirtualIp) != null)
                    VirtualIp = rnd.Next(1, 255) + "." + rnd.Next(1, 255) + "." + rnd.Next(1, 255) + "." + rnd.Next(1, 255);
                return VirtualIp;
            }
        }

        public SSPClient GetClient(string VirtualIp)
        {
            lock (Clients)
            {
                for (int i = 0; i < Clients.Count; i++)
                {
                    if (Clients.Values[i].VirtualIP == VirtualIp)
                        return Clients.Values[i];
                }
                return null;
            }
        }

        private void ServerThread(object o)
        {
            //lets check here for clients who failed to send a keep-alive
            //so most likely clients who were disconnected by hardware
            while (Running)
            {
                Thread.Sleep(1000);
                lock (Clients)
                {
                    for (int i = 0; i < Clients.Count; i++)
                    {
                        //Keep-Alives are being sent every 15 second so we give the client >30 seconds
                        if (Clients.Values[i].Connection.KeepAliveSW.Elapsed.Seconds > 30 &&
                            Clients.Values[i].Connection.LastPacketSW.Elapsed.Seconds > 30)
                        {
                            Clients.Values[i].Disconnect(DisconnectReason.HardwareDisconnection);
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Kill all the clients connected and close the server
        /// </summary>
        public void Dispose()
        {
            this.Running = false;
            this.TcpServer.Close();

            lock (Clients)
            {
                for (int i = 0; i < Clients.Count; i++)
                {
                    try { Clients.Values[i].Handle.Close(); } catch { } //just close
                    Clients.Values[i].Disconnect(DisconnectReason.ServerShuttingDown);
                }
            }
            Clients.Clear();
        }
    }
}