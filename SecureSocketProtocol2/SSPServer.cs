using SecureSocketProtocol2.Misc;
using SecureSocketProtocol2.Network;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace SecureSocketProtocol2
{
    public abstract class SSPServer<ClientType> : IDisposable
    {
        public abstract void onConnectionAccept(ClientType client);
        public abstract void onConnectionClosed(ClientType client);
        public abstract void onException(Exception ex);

        internal object AuthLock = new object();
        internal Socket TcpServer;
        internal Socket UdpServer;
        private SocketAsyncEventArgs asyncSocket;
        private SocketAsyncEventArgs udpAsyncSocket;
        public ServerProperties serverProperties { get; private set; }
        private Type baseClient;
        private SortedList<decimal, SSPClient> Clients;
        private Random random = new Random(DateTime.Now.Millisecond);
        private RandomDecimal randomDecimal = new RandomDecimal(DateTime.Now.Millisecond);
        private bool Running = false;
        internal PrivateKeyHandler KeyHandler;

        /// <summary>
        /// Initialize a new SSPServer
        /// </summary>
        /// <param name="serverProperties">The properties for the server</param>
        public SSPServer(ServerProperties serverProperties)
        {
            if (serverProperties == null)
                throw new ArgumentNullException("serverProperties");

            this.KeyHandler = new PrivateKeyHandler();
            this.serverProperties = serverProperties;
            this.Clients = new SortedList<decimal, SSPClient>();
            this.baseClient = typeof(ClientType);
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

            this.asyncSocket = new SocketAsyncEventArgs();
            this.asyncSocket.Completed += AsyncAction;
            //ThreadPool.QueueUserWorkItem(ServerThread);
            this.Running = true;

            if (!this.TcpServer.AcceptAsync(this.asyncSocket))
                AsyncAction(null, this.asyncSocket);
        }

        int tempId = 0;
        private void AsyncAction(object o, SocketAsyncEventArgs e)
        {
            if (e.SocketError != SocketError.Success)
                return;

            switch(e.LastOperation)
            {
                case SocketAsyncOperation.Accept:
                {
                    //keep receiving connections
                    SSPClient client = (SSPClient)Activator.CreateInstance(baseClient, serverProperties.BaseClientArguments);
                    client.Handle = e.AcceptSocket;
                    client.Connection = new Connection(client);
                    client.RemoteIp = ((IPEndPoint)e.AcceptSocket.RemoteEndPoint).Address.ToString();
                    client.ClientId = randomDecimal.NextDecimal();//new Random(DateTime.Now.Millisecond).Next(0, 1000); //tempId++;//
                    client.ServerAllowsReconnecting = client.ReconnectAtDisconnect;
                    client.ServerSided = true;

                    lock(Clients)
                    {
                        while(Clients.ContainsKey(client.ClientId))
                            client.ClientId = randomDecimal.NextDecimal();
                        Clients.Add(client.ClientId, client);
                    }

                    //accept new client
                    e.AcceptSocket = null;
                    if (!this.TcpServer.AcceptAsync(this.asyncSocket))
                        AsyncAction(null, this.asyncSocket);

                    try
                    {
                        if (!client.ServerHandshake(serverProperties, this.UdpServer, GetClients, KeyHandler))
                        {
                            lock (Clients)
                            {
                                if (Clients.ContainsKey(client.ClientId))
                                    Clients.Remove(client.ClientId);
                            }
                            client.Disconnect();
                            return;
                        }
                    }
                    catch(Exception ex)
                    {
                        onException(ex);
                        client.Disconnect();
                        return;
                    }
                    client.State = ConnectionState.Open;

                    try
                    {
                        client.onRegisterMessages(client.MessageHandler);
                    }
                    catch (Exception ex)
                    {
                        client.onException(ex);
                    }

                    client.StartReceiver();
                    client.onClientConnect();
                    onConnectionAccept((ClientType)((object)client));
                    break;
                }
            }
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
                            Clients.Values[i].Disconnect();
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
                    Clients.Values[i].Disconnect();
                }
            }
            Clients.Clear();
        }
    }
}