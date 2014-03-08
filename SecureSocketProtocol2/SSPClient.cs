using SecureSocketProtocol2.Misc;
using SecureSocketProtocol2.Network;
using SecureSocketProtocol2.Network.Messages;
using SecureSocketProtocol2.Plugin;
using SecureSocketProtocol2.SocksProxy;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Timers;
using SecureSocketProtocol2.Encryptions;
using System.Security.Cryptography;
using SecureSocketProtocol2.Network.Protections;
using SecureSocketProtocol2.Hashers;
using SecureSocketProtocol2.Network.Messages.UDP;
using SecureSocketProtocol2.Network.Messages.TCP;
using SecureSocketProtocol2.Network.Handshake;
using SecureSocketProtocol2.Network.Messages.TCP.Handshake;
using SecureSocketProtocol2.Network.Messages.TCP.Channels;
using SecureSocketProtocol2.Shared;
using SecureSocketProtocol2.Network.Messages.TCP.LiteCode;
using SecureSocketProtocol2.Interfaces;

namespace SecureSocketProtocol2
{
    public abstract class SSPClient : IClient
    {
        public abstract void onClientConnect();
        public abstract void onValidatingComplete();
        public abstract void onDisconnect(DisconnectReason Reason);
        public abstract void onKeepAlive();
        public abstract void onException(Exception ex, ErrorType errorType);
        public abstract void onReconnect();
        public abstract void onNewChannelOpen(Channel channel);
        public abstract void onShareClasses();
        public abstract bool onVerifyCertificate(CertInfo certificate);
        public abstract void onAddProtection(Protection protection);
        public abstract bool onAuthentication(string Username, string Password);
        public abstract void onAuthenticated();
        public abstract void onNewStreamOpen(SecureStream stream);

        //security goes here
        /// <summary> This will add trash at the end of the header, faking the data and making it more difficult. The server and client must have it set to the same count </summary>
        public abstract uint HeaderTrashCount { get; }
        /// <summary>
        /// Choose a number between 0-65000 taking a high number is good, this option is for setting the key randomly between random data to confuse the attacker,
        /// This is a high security risk for taking a low number or exposing the number you've chosen, this number must also match at the client side
        /// </summary>
        public abstract uint PrivateKeyOffset { get; }

        /// <summary>
        /// This method is only for the server-side,
        /// The plugins you would like the server to use and the client must also have these plugins in order to let him be connected,
        /// This method should only be called once.
        /// </summary>
        /// <returns>All the plugins the server should use</returns>
        public abstract IPlugin[] onGetPlugins();

        public Connection Connection { get; set; }
        public Socket Handle { get; internal set; }
        internal Socket UdpHandle { get; set; }
        internal IPEndPoint UdpEndPoint;
        internal bool UdpHandshaked = false;
        internal byte[] UdpHandshakeCode;
        internal bool ServerSided { get; set; }

        public System.Timers.Timer KeepAliveTimer { get; private set; }
        internal SortedList<ulong, Channel> channels;
        internal SyncObject ChannelSyncObject;
        internal Type baseChannel;
        internal object[] baseChannelArgs;
        public bool isUsingProxy { get; private set; }
        public string RemoteIp { get; internal set; }
        public decimal ClientId { get; internal set; }
        public bool ReconnectAtDisconnect { get; set; }
        public bool ServerAllowsReconnecting { get; internal set; }
        internal bool CompletedHandshake { get; private set; }
        public CertInfo Certificate { get; internal set; }
        internal bool UseUDP { get; set; } //it's being used in the HandShake
        public bool Handshaked { get; internal set; }

        public ulong TotalBytesIn { get { return Connection.BytesIn; } }
        public ulong TotalBytesOut { get { return Connection.BytesOut; } }

        /// <summary>
        /// A server-client time synchronisation, Server takes the lead in having the time.
        /// </summary>
        public DateTime TimeSync
        {
            get
            {
                if (TimeSyncSW == null)
                    return _timeSync;
                return _timeSync.Add(TimeSyncSW.Elapsed);
            }
            private set
            {
                this._timeSync = value;
            }
        }
        internal DateTime _timeSync;
        internal Stopwatch TimeSyncSW; //used for updating the TimeSync

        /// <summary> This object is only being used client-sided </summary>
        private SocketAsyncEventArgs UdpAsyncReceiveEvent;
        internal SyncObject UdpSyncObject;

        /// <summary>
        /// Shows to which side he belongs, Running at the Server or is it a Client
        /// </summary>
        public PeerSide PeerSide { get; private set; }

        /// <summary>
        /// A random seed that was provied by the server
        /// </summary>
        public uint Seed { get { return Connection.messageHandler.Seed; } }

        /// <summary>
        /// The Token is being used as security ID to identify the client
        /// </summary>
        internal decimal Token { get; set; }
        internal bool ConnectionClosedNormal = false;
        internal ClientProperties Properties;


        public PluginSystem Plugins
        {
            get
            {
                return Connection.pluginSystem;
            }
        }

        public uint ReconnectionCount { get; internal set; }

        /// <summary> The object that carries along with the SSPClient </summary>
        public object Tag { get; set; }

        [DefaultValue(ConnectionState.Closed)]
        public ConnectionState State { get; internal set; }

        public DeepPacketInspection DPI
        {
            get { return Connection.DPI; }
        }
        public bool Connected
        {
            get
            {
                return Connection.Connected;
            }
            private set
            {
                Connection.Connected = value;
            }
        }
        public bool MultiThreadProcessing
        {
            get;
            set;
        }

        public string HostIp
        {
            get
            {
                return ((IPEndPoint)Handle.RemoteEndPoint).Address.ToString();
            }
        }
        public string HostPort
        {
            get
            {
                return ((IPEndPoint)Handle.RemoteEndPoint).Port.ToString();
            }
        }

        /// <summary>
        /// The message handler handles all the messages
        /// </summary>
        public MessageHandler MessageHandler
        {
            get { return Connection.messageHandler; }
        }

        /// <summary>
        /// Initialize the client at the server side
        /// </summary>
        /// <param name="BaseChannel">The class to use when a channel is created</param>
        /// <param name="BaseChannelArgs">The arguments used to initialize the BaseChannel</param>
        /// <param name="AllowReconnect">Allow the client to be able to re-connected when disconnected for a short period of time</param>
        public SSPClient(Type BaseChannel, object[] BaseChannelArgs, bool AllowReconnect = true)
        {
            this.channels = new SortedList<ulong, Channel>();
            this.ReconnectAtDisconnect = AllowReconnect;
            this.baseChannel = BaseChannel;
            this.baseChannelArgs = BaseChannelArgs;
        }

        /// <summary>
        /// Create a connection
        /// </summary>
        /// <param name="HostIp">The destination to connect to</param>
        /// <param name="Port">The port</param>
        /// <param name="BaseChannel">The class to use when a channel is created</param>
        /// <param name="BaseChannelArgs">The arguments used to initialize the BaseChannel</param>
        /// <param name="PrivateKey">The private key is being used for if a certificate is being used</param>
        /// <param name="KeyFiles">If keyfiles are being used it will make it harder to decrypt the traffic</param>
        /// <param name="Username">If authenication is being used fill it in or else keep it empty, the server will response "Username or Password is wrong" if username/password is wrong or you filledin a username/password even though the server does not expects it</param>
        /// <param name="Password">If authenication is being used fill it in or else keep it empty, the server will response "Username or Password is wrong" if username/password is wrong or you filledin a username/password even though the server does not expects it</param>
        /// <param name="proxySettings">If you want to use a proxy</param>
        /// <param name="ConnectingTimeout">Set the connecting timeout in milliseconds</param>
        public SSPClient(string HostIp, ushort Port, Type BaseChannel, object[] BaseChannelArgs, byte[] PrivateKey, Stream[] KeyFiles = null, string Username = "", string Password = "",
                         ProxySettings proxySettings = null, int ConnectingTimeout = 30000)
            : this(BaseChannel, BaseChannelArgs)
        {
            if (PrivateKey == null || (PrivateKey != null && PrivateKey.Length <= 16))
                throw new ArgumentException("The private key must be longer then 16 in length", "PrivateKey");

            this.Properties = new ClientProperties(HostIp, Port, BaseChannel, BaseChannelArgs, PrivateKey, KeyFiles, proxySettings, ConnectingTimeout, Username, Password);
            Connect(ConnectionState.Open);
        }

        private void KeepAlive_Timer(object source, ElapsedEventArgs e)
        {
            lock(Connection)
            {
                if(Connection.Connected)
                {
                    Connection.SendPayload(new MsgKeepAlive(), PacketId.KeepAlive);
                }
            }
        }

        internal void Connect(ConnectionState State)
        {
            IPAddress[] resolved = Dns.GetHostAddresses(Properties.HostIp);
            string DnsIp = "";

            for (int i = 0; i < resolved.Length; i++)
            {
                if (resolved[i].AddressFamily == AddressFamily.InterNetwork)
                {
                    DnsIp = resolved[i].ToString();
                    break;
                }
            }

            if (DnsIp == "")
                throw new Exception("Unable to resolve \"" + Properties.HostIp + "\" by using DNS");

            if (Properties.proxySettings == null)
            {
                do
                {
                    this.Handle = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    IAsyncResult result = this.Handle.BeginConnect(new IPEndPoint(resolved[0], Properties.Port), (IAsyncResult ar) =>
                    {
                        try
                        {
                            this.Handle.EndConnect(ar);
                        }
                        catch { /* Will throw a error if connection couldn't be made */ }
                    }, null);

                    Stopwatch sw = Stopwatch.StartNew();
                    if (Properties.ConnectingTimeout > 0)
                        result.AsyncWaitHandle.WaitOne(Properties.ConnectingTimeout);
                    else
                        result.AsyncWaitHandle.WaitOne();
                    sw.Stop();
                    Properties.ConnectingTimeout -= (int)sw.ElapsedMilliseconds;

                    if (!this.Handle.Connected)
                        this.Handle.Close();

                } while (Properties.ConnectingTimeout > 0 && !this.Handle.Connected);

                if (!Handle.Connected)
                    throw new Exception("Unable to establish a connection with " + Properties.HostIp + ":" + Properties.Port);
            }
            else
            {
                //this.Handle = new Socks5ProxyClient(Properties.proxySettings.HostIp, Properties.proxySettings.HostPort).CreateConnection();

                Socks5 socks = new Socks5();
                this.Handle = socks.ConnectToSocks5Proxy(Properties.proxySettings.HostIp, Properties.proxySettings.HostPort, Properties.HostIp, Properties.Port, Properties.proxySettings.Username, Properties.proxySettings.Password);
            }

            this.Connection = new Connection(this);
            this.Connected = true;
            
            decimal oldClientId = this.ClientId;
            decimal oldToken = this.Token;

            if (!CreateHandshake(Properties.HostIp, Properties.Port, onGetPlugins()))
                throw new Exception("Failed to complete the handshake");

            if (State == ConnectionState.Reconnecting)
            {
                //tell the server this is a re-connection
                Connection.SendPayload(new MsgReconnect(oldClientId, oldToken), PacketId.Reconnection);

                //wait for the server response

            }

            this.State = ConnectionState.Open;

            try
            {
                onShareClasses();
            }
            catch (Exception ex)
            {
                onException(ex, ErrorType.UserLand);
            }

            StartReceiver();

            if (State != ConnectionState.Reconnecting)
            {
                try
                {
                    onClientConnect();
                }
                catch (Exception ex)
                {
                    onException(ex, ErrorType.UserLand);
                }
            }
        }




        /// <summary> Share a class with other clients to use for remote code execution </summary>
        /// <param name="ClassType">The Class object to share with others</param>
        /// <param name="RemoteInitialize">False: The class will be initialized locally using the "ClassArgs" objects,
        ///                                True: The remote client will give the ClassArgs to use for initializing the object and will ignore the local argument objects</param>
        /// <param name="ClassArgs">The objects to initialize the class with</param>
        public void ShareClass(Type ClassType, bool RemoteInitialize = false, params object[] ClassArgs)
        {
            lock (Connection.SharedClasses)
            {
                if (Connection.SharedClasses.ContainsKey(ClassType.Name))
                    throw new Exception("A class with this name is already shared");
                Connection.SharedClasses.Add(ClassType.Name, new SharedClass(ClassType, this, RemoteInitialize, ClassArgs));
            }
        }

        /// <summary> Share a class with other clients to use for remote code execution </summary>
        /// <param name="Name">The name will be used to make a unique identifier for each shared class</param>
        /// <param name="ClassType">The Class object to share with others</param>
        /// <param name="RemoteInitialize">False: The class will be initialized locally using the "ClassArgs" objects,
        ///                                True: The remote client will give the ClassArgs to use for initializing the object and will ignore the local argument objects</param>
        /// <param name="ClassArgs">The objects to initialize the class with</param>
        public void ShareClass(string Name, Type ClassType, bool RemoteInitialize = false, params object[] ClassArgs)
        {
            lock (Connection.SharedClasses)
            {
                if (Name == null)
                    throw new ArgumentNullException("Name");
                if (Connection.SharedClasses.ContainsKey(Name))
                    throw new Exception("A class with this name is already shared");
                Connection.SharedClasses.Add(Name, new SharedClass(ClassType, this, RemoteInitialize, ClassArgs));
            }
        }

        public InterfacePrototype GetSharedClass<InterfacePrototype>(string name, params object[] RemoteArgs)
        {
            SyncObject syncObject = null;
            lock (Connection.Requests)
            {
                Random rnd = new Random(DateTime.Now.Millisecond);
                int RequestId = RequestId = rnd.Next();
                while (Connection.Requests.ContainsKey(RequestId))
                    RequestId = rnd.Next();
                syncObject = new SyncObject(this);
                Connection.Requests.Add(RequestId, syncObject);
                Connection.SendMessage(new MsgGetSharedClass(name, RemoteArgs, RequestId), PacketId.LiteCode); //send message
            }

            ReturnResult result = syncObject.Wait<ReturnResult>(null, 30000); //wait for response
            if (result == null)
                throw new Exception("A timeout occured" + syncObject.TimedOut + ", " + syncObject.Pulsed + "..." + Connection.Connected);
            if (result.ExceptionOccured)
                throw new Exception(result.exceptionMessage);
            if (result.ReturnValue == null)
                throw new Exception("The shared class \"" + name + "\" could not be found in the remote client");
            
            SharedClass c = (SharedClass)result.ReturnValue;
            c.Client = this;
            InterfacePrototype tmp = DynamicClassCreator.CreateDynamicClass<InterfacePrototype>(c);

            lock (Connection.SharedClasses)
            {
                Connection.InitializedClasses.Add(c.SharedId, c);
            }
            return tmp;
        }

        internal SSPError SendUdpMessage(IMessage message, UdpPAcketId packetId)
        {
            lock (UdpHandle)
            {
                PayloadWriter pw = new PayloadWriter();
                pw.WriteDecimal(this.ClientId);
                pw.WriteByte((byte)packetId);
                pw.WriteUInteger(Connection.messageHandler.GetMessageId(message.GetType()));
                message.WritePacket(message, ref pw);
                this.UdpHandle.SendTo(pw.GetBuffer(), 0, pw.Length, SocketFlags.None, this.UdpEndPoint);
                return SSPError.ErrorSuccess;
            }
        }

        private int RequestNameToId(string Name)
        {
            using (SHA1 hasher = SHA1.Create())
            {
                byte[] temp = hasher.ComputeHash(ASCIIEncoding.Unicode.GetBytes(Name));
                return BitConverter.ToInt32(temp, 0) + BitConverter.ToInt32(temp, 4) + BitConverter.ToInt32(temp, 8) + BitConverter.ToInt32(temp, 12);
            }
        }

        public void ApplyPrivateKey(byte[] Key)
        {
            if (Key == null)
                throw new ArgumentNullException("Key");
            if (Key.Length < 16)
                throw new ArgumentException("Key must be atleast 16 in length");
            Connection.protection.ApplyPrivateKey(Key);
        }

        private bool CreateHandshake(string HostIp, ushort Port, IPlugin[] Plugins)
        {
            this.PeerSide = SecureSocketProtocol2.PeerSide.Client;
            bool UseUdp = false;
            SyncObject syncObject = null;

            onAddProtection(Connection.protection); //no error handling by SSP, this must work or there is simply no connection

            //apply private key
            ApplyPrivateKey(Properties.PrivateKey);

            //apply the KeyFiles
            if (Properties.KeyFiles != null)
            {
                foreach (Stream stream in Properties.KeyFiles)
                {
                    while (stream.Position < stream.Length)
                    {
                        byte[] data = new byte[32768];
                        int read = stream.Read(data, 0, data.Length);

                        if (read <= 0)
                            break;

                        Array.Resize(ref data, read);
                        ApplyPrivateKey(data);
                    }
                }
            }

            ClientSideHandshake handShake = new ClientSideHandshake(this, Properties);
            if (!handShake.DoHandshake())
            {
                Disconnect(DisconnectReason.HandShakeFailed);
                throw new Exception("An unexpected error occured in the HandShake");
            }
            this.CompletedHandshake = true;
            return true;
        }

        private bool onClientUdpHandshake(IMessage message)
        {
            MsgUdpValidation validation = message as MsgUdpValidation;

            if (validation == null)
                return false;

            if (validation.Validation.Length == 5)
            {
                //for now hardcoded values, need to change this soon!
                return validation.Validation[0] == 0x8F && validation.Validation[1] == 0xFF &&
                       validation.Validation[2] == 0x46 && validation.Validation[3] == 0x4F &&
                       validation.Validation[4] == 0x37;
            }
            return false;
        }

        internal unsafe bool ServerHandshake(ServerProperties serverProperties, Socket UdpClient, GetClientsDelegate getClientsDelegate, PrivateKeyHandler KeyHandler)
        {
            this.PeerSide = SecureSocketProtocol2.PeerSide.Server;

            //check certificate info
            if (serverProperties.ServerCertificate.PrivateKey == null || (serverProperties.ServerCertificate.PrivateKey != null && serverProperties.ServerCertificate.PrivateKey.Length <= 16))
                throw new ArgumentException("The private key must be longer then 16 in length", "PrivateKey");

            onAddProtection(Connection.protection); //no error handling by SSP, this must work or there is simply no connection

            //apply private key
            ApplyPrivateKey(serverProperties.ServerCertificate.PrivateKey);

            if (serverProperties.KeyFiles != null)
            {
                foreach (Stream stream in serverProperties.KeyFiles)
                {
                    while (stream.Position < stream.Length)
                    {
                        byte[] data = new byte[32768];
                        int read = stream.Read(data, 0, data.Length);

                        if (read <= 0)
                            break;

                        Array.Resize(ref data, read);
                        ApplyPrivateKey(data);
                    }
                }
            }

            ServerSideHandshake handShake = new ServerSideHandshake(this, serverProperties, UdpClient, getClientsDelegate, KeyHandler);
            if (!handShake.DoHandshake())
            {
                Disconnect(DisconnectReason.HandShakeFailed);
                throw new Exception("An unexpected error occured in the HandShake");
            }

            this.CompletedHandshake = true;
            this.Connection.KeepAliveSW = Stopwatch.StartNew();
            return true;
        }

        internal void StartReceiver()
        {
            this.Connection.StartNetworkStream();

            if (UdpHandle != null)
            {
                this.UdpAsyncReceiveEvent = new SocketAsyncEventArgs();
                this.UdpAsyncReceiveEvent.SetBuffer(new byte[70000], 0, 70000);
                this.UdpAsyncReceiveEvent.RemoteEndPoint = this.UdpEndPoint;
                this.UdpAsyncReceiveEvent.Completed += AsyncSocketCallback;
                this.UdpAsyncReceiveEvent.AcceptSocket = this.UdpHandle;

                if (!UdpHandle.ReceiveFromAsync(UdpAsyncReceiveEvent))
                    AsyncSocketCallback(null, UdpAsyncReceiveEvent);
            }
        }

        /// <summary>
        /// Opens a channel, this will create a new channel where data will be tunneled through
        /// </summary>
        /// <param name="channel">The channel you want to open</param>
        /// <param name="Tag">The object want the channel to carry</param>
        /// <returns>Was opening a channel successful</returns>
        public ChannelError OpenChannel(Channel channel)
        {
            try
            {
                lock(channels)
                {
                    //first set the default info
                    channel.Connection = Connection;
                    channel.Client = this;
                    channel.State = ConnectionState.Open;

                    this.ChannelSyncObject = new SyncObject(Connection);
                    this.Connection.SendMessage(new MsgOpenChannel(), PacketId.OpenChannel);
                    MsgOpenChannelResponse response = this.ChannelSyncObject.Wait<MsgOpenChannelResponse>(default(MsgOpenChannelResponse), 30000);

                    if(response == null)
                        return ChannelError.Timeout;
                    if(!response.success)
                        return ChannelError.Timeout;

                    channel.ConnectionId = response.ConnectionId;
                    channels.Add(channel.ConnectionId, channel);

                    try
                    {
                        channel.onChannelOpen();
                    } catch(Exception ex)
                    {
                        onException(ex, ErrorType.UserLand);
                    }
                    return ChannelError.Success;
                }
            }
            catch(Exception ex)
            {
                onException(ex, ErrorType.Core);
            }
            return ChannelError.InitializeError;
        }

        internal unsafe void AsyncSocketCallback(object o, SocketAsyncEventArgs e)
        {
            if (e.LastOperation == SocketAsyncOperation.ReceiveFrom)
            {
                try
                {
                    if (e.BytesTransferred >= 21)
                    {
                        if (!Connected)
                            return; //TCP Client is disconnected so don't process UDP packets

                        //before we process the packet, does the IP/LocalPort match ?
                        if (UdpHandshaked && BitConverter.ToUInt32(this.UdpEndPoint.Address.GetAddressBytes(), 0) !=
                                             BitConverter.ToUInt32(((IPEndPoint)e.RemoteEndPoint).Address.GetAddressBytes(), 0))
                        {
                            //simply skip and don't disconnect TCP
                            //I'll add later a option to the server to disconnect or not just for safety reasons ;)
                            return;
                        }

                        //decrypt traffic here
                        PayloadReader pr = new PayloadReader(e.Buffer);
                        decimal clientId = pr.ReadDecimal();

                        //extra check
                        if (this.ClientId != clientId)
                            return;

                        UdpPAcketId packetId = (UdpPAcketId)pr.ReadByte();
                        uint MessageId = pr.ReadUInteger();

                        IMessage message = null;
                        try
                        {
                            message = Connection.messageHandler.HandleUdpMessage(pr, MessageId);

                            if (message != null)
                            {
                                message.RawSize = e.BytesTransferred;
                            }
                        }
                        catch (Exception ex)
                        {
                            return;
                        }


                        //process packet
                        if (UdpHandshaked)
                        {
                            switch (packetId)
                            {
                                case UdpPAcketId.Payload:
                                {
                                    //onReceiveUdpMessage(message);
                                    break;
                                }
                            }
                        }
                        else
                        {
                            MsgUdpHandshake HandshakeMsg = message as MsgUdpHandshake;
                            if (HandshakeMsg != null)
                            {
                                fixed (byte* ptr = HandshakeMsg.HandshakeCode, ptr2 = this.UdpHandshakeCode)
                                {
                                    if (NativeMethods.memcmp(ptr, ptr2, (uint)this.UdpHandshakeCode.Length) == 0)
                                    {
                                        this.UdpEndPoint = e.RemoteEndPoint as IPEndPoint;
                                        Connection.SendPayload(new MsgUdpValidation(new byte[] { 0x8F, 0xFF, 0x46, 0x4F, 0x37 }), PacketId.Unknown);
                                        UdpHandshaked = true;
                                        UdpSyncObject.Value = true;
                                        UdpSyncObject.Pulse();
                                    }
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    onException(ex, ErrorType.Core);
                }

                if (PeerSide == SecureSocketProtocol2.PeerSide.Client)
                {
                    if (!UdpHandle.ReceiveFromAsync(UdpAsyncReceiveEvent))
                        AsyncSocketCallback(null, UdpAsyncReceiveEvent);
                }
            }
            else
            {

            }
        }

        public void Disconnect()
        {
            Disconnect(DisconnectReason.UserDisconnection);
        }

        internal void Disconnect(DisconnectReason Reason)
        {
            //disconnect all plugins
            try
            {
                for (int i = 0; i < Plugins.Plugins.Length; i++)
                {
                    if (Plugins.Plugins[i].AllowPluginHooks() && Plugins.Plugins[i].Hooks.Count > 0)
                    {
                        foreach (IPluginHook hook in Plugins.Plugins[i].Hooks)
                            hook.onClientDisconnected();
                    }

                    try { Plugins.Plugins[i].onClientDisconnected(); } catch { }
                }
            }
            catch (Exception ex)
            {
                onException(ex, ErrorType.UserLand);
            }

            try
            {
                lock (Connection)
                {
                    if (this.Connected && !ConnectionClosedNormal)
                    {
                        Connection.SendPayload(new MsgDisconnected(Reason), PacketId.Disconnected);
                        ConnectionClosedNormal = true;
                    }
                }
            }
            catch (Exception ex)
            {
                onException(ex, ErrorType.Core);
            }

            try
            {
                Handle.Close();
            }
            catch { }

            try
            {
                if (UdpHandle != null)
                    UdpHandle.Close();
            }
            catch (Exception ex)
            {
                onException(ex, ErrorType.Core);
            }

            this.State = ConnectionState.Closed;
            this.Connected = false;

            try
            {
                onDisconnect(Reason);
            }
            catch (Exception ex)
            {
                onException(ex, ErrorType.UserLand);
            }
        }
    }
}