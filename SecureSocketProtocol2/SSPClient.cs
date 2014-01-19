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

namespace SecureSocketProtocol2
{
    public abstract class SSPClient : IClient
    {
        public abstract void onReceiveMessage(IMessage message);
        public abstract void onReceiveUdpData(byte[] data, int size);
        public abstract void onClientConnect();
        public abstract void onValidatingComplete();
        public abstract void onDisconnect();
        public abstract void onDeepPacketInspection(IMessage message);
        public abstract void onKeepAlive();
        public abstract void onException(Exception ex);
        public abstract void onReconnect();
        public abstract void onNewChannelOpen(Channel channel);
        public abstract void onRegisterMessages(MessageHandler messageHandler);
        public abstract bool onVerifyCertificate(CertInfo certificate);
        public abstract void onAddProtection(Protection protection);
        public abstract bool onAuthentication(string Username, string Password);
        public abstract void onAuthenticated();

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
        public Socket Handle { get; set; }
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
        private DiffieHellman diffieHellman;
        internal bool CompletedHandshake { get; private set; }
        private SocketAsyncEventArgs UdpAsyncReceiveEvent;
        private SyncObject UdpSyncObject;
        public CertInfo Certificate { get; private set; }

        public byte[] PrivateKey
        {
            get { return diffieHellman.Key; }
        }

        /// <summary>
        /// A random seed that was provied by the server
        /// </summary>
        public uint Seed { get; private set; }

        /// <summary>
        /// The Token is being used as security ID to identify the client
        /// </summary>
        internal decimal Token { get; private set; }
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
            this.diffieHellman = new DiffieHellman(256);
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
                    Connection.SendPacket(new MsgKeepAlive(), PacketId.KeepAlive, true);
                }
            }
        }

        internal void Connect(ConnectionState State)
        {
            if (Properties.proxySettings == null)
            {
                do
                {
                    this.Handle = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    IAsyncResult result = this.Handle.BeginConnect(new IPEndPoint(IPAddress.Parse(Properties.HostIp), Properties.Port), (IAsyncResult ar) =>
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
                Connection.SendPacket(new MsgReconnect(oldClientId, oldToken), PacketId.Reconnection);

                //wait for the server response

            }

            this.State = ConnectionState.Open;

            try
            {
                onRegisterMessages(this.MessageHandler);
            }
            catch (Exception ex)
            {
                onException(ex);
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
                    onException(ex);
                }
            }
        }

        /// <summary>
        /// Sends the data to a transfer queue which will handle the data in a different thread, this will improve performance with small data
        /// </summary>
        /// <param name="data">The data you want to sent</param>
        /// <param name="offset">The index where the data starts</param>
        /// <param name="length">The length of the data</param>
        public void SendPacketQueue(byte[] data, int offset, int length)
        {
            lock(Connection)
            {
                Connection.SendPacketQueue(data, offset, length, PacketId.Payload);
            }
        }

        /// <summary>
        /// Sent data to the other side
        /// </summary>
        /// <param name="message">The message you want to sent</param>
        /// <param name="compress">If you want to compress the data you're sending</param>
        /// <param name="cache">Cache the data you want to sent, this will decrease the traffic at a very high ratio, could decrease performance at encrypted/compressed data</param>
        /// <returns>Successful or error</returns>
        public SSPError SendMessage(IMessage message, bool compress = true, bool cache = true)
        {
            lock (Connection)
            {
                if (State == ConnectionState.Closed)
                    return SSPError.ClientDisconnected;
                while (State == ConnectionState.Reconnecting)
                    Thread.Sleep(100);

                lock (Connection)
                {
                    Connection.SendPacket(message, PacketId.Payload, compress, cache);
                }
                return SSPError.ErrorSuccess;
            }
        }

        /// <summary>
        /// Send data to the other side using the UDP protocol
        /// </summary>
        /// <param name="data">The data you want to sent</param>
        /// <param name="offset">The index where the data starts</param>
        /// <param name="length">The length of the data</param>
        /// <returns>Successful or error</returns>
        public SSPError SendUdpPacket(byte[] data, int offset, int length)
        {
            lock (UdpHandle)
            {
                return SendUdpPacket(data, offset, length, UdpPAcketId.Payload);
            }
        }

        internal SSPError SendUdpPacket(byte[] data, int offset, int length, UdpPAcketId packetId)
        {
            lock (UdpHandle)
            {
                PayloadWriter pw = new PayloadWriter();
                pw.WriteDecimal(this.ClientId);
                pw.WriteByte((byte)packetId);
                pw.WriteBytes(data, offset, length);
                byte[] payload = pw.GetBuffer();

                //add encryption here

                this.UdpHandle.SendTo(payload, 0, pw.Length, SocketFlags.None, this.UdpEndPoint);
                return SSPError.ErrorSuccess;
            }
        }

        private bool CreateHandshake(string HostIp, ushort Port, IPlugin[] Plugins)
        {
            //apply private key
            Connection.protection.ApplyPrivateKey(Properties.PrivateKey);

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
                        Connection.protection.ApplyPrivateKey(data);
                    }
                }
            }

            Connection.SendPacket(new MsgValidation(Connection.VALIDATION), PacketId.Unknown);
            SyncObject syncObject = null;
            bool UseUdp = false;

            if (!(syncObject = Connection.Receive((IMessage message) =>
            {
                MsgValidation validation = message as MsgValidation;
                if (validation != null)
                    return validation.ValidationSuccess;
                return false;
            })).Wait<bool>(false, 30000))
            {
                Disconnect();
                if (syncObject.TimedOut)
                    throw new Exception("A timeout occured, this means the server did not respond for ~30 seconds");
                throw new Exception("Incorrect signature");
            }

            if (!(syncObject = Connection.Receive((IMessage message) =>
            {
                MsgMessageSeed mms = message as MsgMessageSeed;

                if (mms != null)
                {
                    this.Seed = mms.Seed;
                    Connection.messageHandler.RegisterMessages(mms.Seed);
                    return true;
                }
                return false;
            })).Wait<bool>(false, 30000))
            {
                Disconnect();
                if (syncObject.TimedOut)
                    throw new Exception("A timeout occured, this means the server did not respond for ~30 seconds");
                throw new Exception("Failed to retrieve the message seed.");
            }

            //wait for RSA from server
            RSAEncryption RSA = null;
            if (!Connection.Receive((IMessage message) =>
            {
                MsgRsaPublicKey rsaKey = message as MsgRsaPublicKey;

                if (rsaKey != null)
                {
                    RSA = new RSAEncryption(Connection.RSA_KEY_SIZE, "", rsaKey.PublicKey, true); // <- private key not public, don't get confused of the argument ITS PRIVATE KEY
                    return true;
                }
                return false;
            }).Wait<bool>(false, 30000))
            {
                Disconnect();
                return false;
            }            

            bool BlockedCertificate = false;
            if (!(syncObject = Connection.Receive((IMessage message) =>
            {
                MsgServerEncryption mse = message as MsgServerEncryption;

                if (mse != null)
                {
                    UseUdp = mse.UseUdp;

                    //read the Diffie-Hellman key
                    long index = PrivateKeyOffset % 65535;
                    if (index <= 4)
                        index = 10;

                    byte[] diffieLen = new byte[4];
                    Array.Copy(mse.Key, index - 4, diffieLen, 0, diffieLen.Length);
                    byte[] diffieData = new byte[BitConverter.ToInt32(diffieLen, 0)];
                    Array.Copy(mse.Key, index, diffieData, 0, diffieData.Length); //copy the diffie-hellman key in between random data

                    //fix RSA Encrypted Data
                    Array.Copy(mse.Key, mse.Key.Length - (diffieLen.Length + diffieData.Length), mse.Key, index-4, diffieLen.Length + diffieData.Length);
                    Array.Resize(ref mse.Key, mse.Key.Length - (diffieLen.Length + diffieData.Length)); //set original size back

                    //check if key is original
                    uint KeyHash = BitConverter.ToUInt32(new CRC32().ComputeHash(mse.Key), 0);

                    string DiffieKey = ASCIIEncoding.ASCII.GetString(diffieData);
                    diffieHellman.GenerateResponse(DiffieKey);
                    this.Certificate = mse.certificate;

                    if (!onVerifyCertificate(mse.certificate))
                    {
                        BlockedCertificate = true;
                        return false;
                    }

                    Connection.SendPacket(new MsgDiffiehellman(diffieHellman.ToString()), PacketId.Unknown);
                    Connection.protection.ApplyPrivateKey(diffieHellman.Key); //apply salt key
                    mse.Key = RSA.Decrypt(mse.Key, 0, mse.Key.Length);//decrypt key
                    Connection.protection.ApplyPrivateKey(mse.Key); //apply secure key
                    return true;
                }
                return false;
            })).Wait<bool>(false, 30000))
            {
                Disconnect();
                if (!BlockedCertificate)
                {
                    if (syncObject.TimedOut)
                        throw new Exception("A timeout occured, this means the server did not respond for ~30 seconds");
                    throw new Exception("Diffie-Hellman key-exchange failed.");
                }
                throw new Exception("The certificate provided by the server was blocked by the user");
            }

            //let's do the user/pass authenication
            if ((Properties.Username != null && Properties.Username.Length > 0) &&
                (Properties.Password != null && Properties.Password.Length > 0))
            {
                Connection.SendPacket(new MsgAuthenication(Properties.Username, Properties.Password), PacketId.Unknown);
                if (!(syncObject = Connection.Receive((IMessage message) =>
                {
                    MsgAuthenicationSuccess authResponse = message as MsgAuthenicationSuccess;

                    if (authResponse != null)
                    {
                        return authResponse.Success;
                    }
                    return false;
                })).Wait<bool>(false, 30000))
                {
                    Disconnect();
                    if (syncObject.TimedOut)
                        throw new Exception("A timeout occured, this means the server did not respond for ~30 seconds");
                    throw new Exception("Username or Password is incorrect");
                }
            }
            Connection.SendPacket(new MsgOk(), PacketId.Unknown); //tell the server it's ok

            try
            {
                //at this point you could use extra keyfiles or other security measures
                onAuthenticated();
            }
            catch (Exception ex)
            {
                onException(ex);
            }

            if (!(syncObject = Connection.Receive((IMessage message) =>
            {
                MsgClientInfo mci = message as MsgClientInfo;

                if (mci != null)
                {
                    this.ClientId = mci.ClientId;
                    this.Token = mci.Token;

                    if (UseUdp)
                    {
                        this.UdpHandshakeCode = mci.UdpHandshakeCode;
                    }
                    return true;
                }
                return false;
            })).Wait<bool>(false, 30000))
            {
                Disconnect();
                if (syncObject.TimedOut)
                    throw new Exception("A timeout occured, this means the server did not respond for ~30 seconds");
                throw new Exception("Failed to retrieve the Client Id");
            }

            //let's process now the UDP protocol
            if (UseUdp)
            {
                this.UdpEndPoint = new IPEndPoint(IPAddress.Parse(HostIp), Port);
                this.UdpHandle = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                SyncObject udpSync = Connection.Receive(onClientUdpHandshake);
                bool UdpSuccess = false;

                PayloadWriter pw = new PayloadWriter();
                pw.WriteDecimal(this.ClientId);
                this.UdpHandle.SendTo(pw.ToByteArray(), this.UdpEndPoint);

                for (int i = 0; i < 35/5; i++)
                {
                    SendUdpPacket(this.UdpHandshakeCode, 0, this.UdpHandshakeCode.Length, UdpPAcketId.Handshake);
                    if (udpSync.Wait<bool>(false, 5000))
                    {
                        UdpSuccess = true;
                        break;
                    }
                }

                if (!UdpSuccess)
                {
                    Disconnect();
                    throw new Exception("The server did not respond in time to acknowledge the UDP connection");
                }
            }

            this.MessageHandler.ResetMessages();

            //handple plugins
            int PluginCount = 0;
            if (!(syncObject = Connection.Receive((IMessage message) =>
            {
                MsgPluginCount MsgCount = message as MsgPluginCount;
                if (MsgCount == null)
                    return false;
                PluginCount = MsgCount.PluginCount;
                return true;
            })).Wait<bool>(false))
            {
                Disconnect();
                if (syncObject.TimedOut)
                    throw new Exception("A timeout occured, this means the server did not respond for ~30 seconds");
                throw new Exception("Failed to retrieve the plugin information");
            }

            if(Plugins.Length != PluginCount)
            {
                Disconnect();
                throw new Exception("The client is missing a few plugin(s), add the plugin(s) in order to connect");
            }
            for (int i = 0; i < PluginCount; i++)
            {
                bool FoundPlugin = false;
                if (!(syncObject = Connection.Receive((IMessage message) =>
                {
                    MsgGetPluginInfo MsgInfo = message as MsgGetPluginInfo;
                    if (MsgInfo == null)
                        return false;

                    for (int j = 0; j < Plugins.Length; j++)
                    {
                        ulong Id = Connection.pluginSystem.GetPluginId(Plugins[j]);
                        if (MsgInfo.PluginId == Id)
                        {
                            Connection.SendPacket(new MsgGetPluginInfoResponse(Plugins[j].Name, Plugins[j].PluginVersion.ToString()), PacketId.Unknown);
                            FoundPlugin = true;
                            break;
                        }
                    }

                    if (!FoundPlugin)
                    {
                        Connection.SendPacket(new MsgGetPluginInfoResponse("", ""), PacketId.Unknown);
                    }
                    return true;
                })).Wait<bool>(false))
                {
                    Disconnect();
                    if (syncObject.TimedOut)
                        throw new Exception("A timeout occured, this means the server did not respond for ~30 seconds");
                    throw new Exception("Failed to retrieve the plugin information");
                }

                if (FoundPlugin)
                {
                    if (!(syncObject = Connection.Receive((IMessage message) =>
                    {
                        MsgInitPlugin msgInit = message as MsgInitPlugin;
                        if (msgInit == null)
                            return false;

                        for (int j = 0; j < Plugins.Length; j++)
                        {
                            ulong Id = Connection.pluginSystem.GetPluginId(Plugins[j]);
                            if (msgInit.PluginId == Id)
                            {
                                try
                                {
                                    Connection.pluginSystem.AddPlugin(Plugins[j]);
                                    Plugins[j].onRegisterMessages(Connection.messageHandler);

                                    try
                                    {
                                        if (Plugins[j].AllowPluginHooks() && Plugins[j].Hooks.Count > 0)
                                        {
                                            foreach (IPluginHook hook in Plugins[j].Hooks)
                                                hook.onClientConnected();
                                        }
                                        Plugins[j].onClientConnected();
                                    }
                                    catch (Exception ex)
                                    {
                                        onException(ex);
                                    }
                                }
                                catch { return false; }
                                break;
                            }
                        }
                        return true;
                    })).Wait<bool>(false))
                    {
                        Disconnect();
                        if (syncObject.TimedOut)
                            throw new Exception("A timeout occured, this means the server did not respond for ~30 seconds");
                        throw new Exception("Failed to retrieve the plugin information");
                    }
                }
            }

            //just to say the server we received it and we're done
            Connection.SendPacket(new MsgOk(), PacketId.Unknown);

            if (!(syncObject = Connection.Receive((IMessage message) =>
            {
                MsgOk msgOk = message as MsgOk;
                if (msgOk != null)
                    return true;
                return false;
            })).Wait<bool>(false))
            {
                Disconnect();
                if (syncObject.TimedOut)
                    throw new Exception("A timeout occured, this means the server did not respond for ~30 seconds");
                throw new Exception("Failed to retrieve an handshake acknowledgement");
            }

            this.CompletedHandshake = true;
            onValidatingComplete();
            return true;
        }

        private bool onClientUdpHandshake(IMessage message)
        {
            //if (payload.Length == 5)
            //    return payload[0] == 0x8F && payload[1] == 0xFF && payload[2] == 0x46 && payload[3] == 0x4F && payload[4] == 0x37;
            return false;
        }

        internal unsafe bool ServerHandshake(ServerProperties serverProperties, Socket UdpClient, GetClientsDelegate getClientsDelegate, PrivateKeyHandler KeyHandler)
        {
            //check certificate info
            if (serverProperties.ServerCertificate.PrivateKey == null || (serverProperties.ServerCertificate.PrivateKey != null && serverProperties.ServerCertificate.PrivateKey.Length <= 16))
                throw new ArgumentException("The private key must be longer then 16 in length", "PrivateKey");

            //apply private key
            Connection.protection.ApplyPrivateKey(serverProperties.ServerCertificate.PrivateKey);

            if (serverProperties.KeyFiles != null)
            {
                foreach (Stream stream in serverProperties.KeyFiles)
                {
                    while (stream.Position < stream.Length)
                    {
                        byte[] data = new byte[32768];
                        int read = stream.Read(data, 0, data.Length);

                        if (read == 0)
                            break;

                        Array.Resize(ref data, read);
                        Connection.protection.ApplyPrivateKey(data);
                    }
                }
            }

            if (!Connection.Receive((IMessage message) =>
            {
                MsgValidation validation = message as MsgValidation;

                if (validation != null)
                {
                    if (validation.ValidationKey.Length != Connection.VALIDATION.Length)
                        return false;

                    fixed (byte* ptr = validation.ValidationKey, ptr2 = Connection.VALIDATION)
                    {
                        if (NativeMethods.memcmp(ptr, ptr2, (uint)Connection.VALIDATION.Length) == 0)
                        {
                            Connection.SendPacket(new MsgValidation(true), PacketId.Unknown);
                            return true;
                        }
                    }
                }
                return false;
            }).Wait<bool>(false, 30000))
            {
                Disconnect();
                return false;
            }
            onValidatingComplete();

            //register the message
            Connection.messageHandler.RegisterMessages(0); //set seed 0 so it generates a new seed
            this.Seed = Connection.messageHandler.Seed;
            Connection.SendPacket(new MsgMessageSeed(Connection.messageHandler.Seed), PacketId.Unknown);










            RSAEncryption RSA = KeyHandler.GetPrivateKey();
            Connection.SendPacket(new MsgRsaPublicKey(RSA.PrivateKey), PacketId.Unknown); //<- private key

            //generate a big random key
            byte[] encryptionKey = new byte[65535];
            new Random(DateTime.Now.Millisecond).NextBytes(encryptionKey);

            //encrypt the key with RSA
            byte[] cryptedKey = RSA.Encrypt(encryptionKey, 0, encryptionKey.Length);
            uint KeyHash = BitConverter.ToUInt32(new CRC32().ComputeHash(cryptedKey), 0);

            diffieHellman = KeyHandler.GetDiffieHellman();
            byte[] diffieStr = ASCIIEncoding.ASCII.GetBytes(diffieHellman.ToString());
            long index = PrivateKeyOffset % cryptedKey.Length;
            if (index <= 4)
                index = 10;
            byte[] diffieLen = BitConverter.GetBytes(diffieStr.Length);

            //create a backup of encrypted RSA data
            byte[] RsaBackup = new byte[diffieLen.Length + diffieStr.Length];
            Array.Copy(cryptedKey, index-4, RsaBackup, 0, RsaBackup.Length); //Rsa Backup Data
            Array.Copy(diffieLen, 0, cryptedKey, index-4, diffieLen.Length); //write Diffie-Hellman key length
            Array.Copy(diffieStr, 0, cryptedKey, index, diffieStr.Length); //copy the diffie-hellman key in between random data
            
            //maybe not secure adding this at the end of the encrypted data but whatever for now
            Array.Resize(ref cryptedKey, cryptedKey.Length + RsaBackup.Length);
            Array.Copy(RsaBackup, 0, cryptedKey, cryptedKey.Length - RsaBackup.Length, RsaBackup.Length);


            CertInfo certificate = new CertInfo(serverProperties.ServerCertificate);
            certificate.FingerPrintMd5 = BitConverter.ToString(MD5.Create().ComputeHash(serverProperties.ServerCertificate.PrivateKey)).Replace("-", "");
            certificate.FingerPrintSha1 = BitConverter.ToString(SHA1.Create().ComputeHash(serverProperties.ServerCertificate.PrivateKey)).Replace("-", "");
            certificate.KeyAlgorithm = "RSA with " + Connection.RSA_KEY_SIZE + "bit";
            certificate.Compression = "";//serverProperties.Compression.ToString();
            certificate.Cipher = "";// serverProperties.Encryption.ToString();
            certificate.HandshakeMethod = "RSA" + Connection.RSA_KEY_SIZE + "-DiffieHellman-AES256";

            if (!serverProperties.ServerCertificate.ShowProtectionMethods)
            {
                certificate.Cipher = "";
                certificate.Checksum = ChecksumHash.None;
                certificate.Compression = "";
                certificate.HandshakeMethod = "";
                certificate.KeyAlgorithm = "";
            }

            this.Certificate = certificate;
            Connection.SendPacket(new MsgServerEncryption(serverProperties.AllowUdp, certificate, cryptedKey, KeyHash), PacketId.Unknown);


            if (!Connection.Receive((IMessage message) =>
            {
                MsgDiffiehellman diffie = message as MsgDiffiehellman;

                if (diffie != null)
                {
                    try
                    {
                        diffieHellman.HandleResponse(diffie.DiffieHellman);
                        Connection.protection.ApplyPrivateKey(diffieHellman.Key); //apply salt-key
                        Connection.protection.ApplyPrivateKey(encryptionKey); //apply secure key
                        return true;
                    }
                    catch { return false; }
                }
                return false;
            }).Wait<bool>(false, 30000))
            {
                Disconnect();
                return false;
            }


            if (serverProperties.UserPassAuthenication)
            {
                if (!Connection.Receive((IMessage message) =>
                {
                    MsgAuthenication msgAuth = message as MsgAuthenication;
                    if (msgAuth != null)
                    {
                        //todo: check password if it only contains the character it should have
                        try
                        {
                            bool success = onAuthentication(msgAuth.Username, msgAuth.Password);
                            Connection.SendPacket(new MsgAuthenicationSuccess(success), PacketId.Unknown);
                        }
                        catch
                        {
                            Connection.SendPacket(new MsgAuthenicationSuccess(false), PacketId.Unknown);
                        }
                        return true;
                    }
                    Connection.SendPacket(new MsgAuthenicationSuccess(false), PacketId.Unknown);
                    return false;
                }).Wait<bool>(false, 30000))
                {
                    Disconnect();
                    return false;
                }
            }

            //just to verify the packet
            if (!Connection.Receive((IMessage message) =>
            {
                MsgOk msgOk = message as MsgOk;
                if (msgOk != null)
                    return true;
                return false;
            }).Wait<bool>(false, 30000))
            {
                Disconnect();
                return false;
            }

            try
            {
                //at this point you could use extra keyfiles or other security measures
                onAuthenticated();
            }
            catch (Exception ex)
            {
                onException(ex);
            }

            Random rnd = new Random(DateTime.Now.Millisecond);
            if (serverProperties.AllowUdp)
            {
                this.UdpHandshakeCode = new byte[50];
                rnd.NextBytes(this.UdpHandshakeCode);
            }

            this.Token = new RandomDecimal(DateTime.Now.Millisecond).NextDecimal();
            Connection.SendPacket(new MsgClientInfo(this.ClientId, this.UdpHandshakeCode, this.Token), PacketId.Unknown);
            this.MessageHandler.ResetMessages();

            if (serverProperties.AllowUdp)
            {
                //let's process the UDP protocol
                this.UdpHandle = UdpClient;
                this.UdpSyncObject = new SyncObject(Connection);
                this.UdpEndPoint = new IPEndPoint(IPAddress.Parse(this.RemoteIp), 0);
                /*this.UdpAsyncReceiveEvent = new SocketAsyncEventArgs();
                this.UdpAsyncReceiveEvent.SetBuffer(new byte[65535], 0, 65535);
                this.UdpAsyncReceiveEvent.RemoteEndPoint = this.UdpEndPoint;
                this.UdpAsyncReceiveEvent.Completed += AsyncSocketCallback;

                if (!UdpClient.ReceiveFromAsync(UdpAsyncReceiveEvent))
                    AsyncSocketCallback(null, UdpAsyncReceiveEvent);*/

                if (!this.UdpSyncObject.Wait<bool>(false, 30000))
                {
                    Disconnect();
                    return false;
                }
            }

            IPlugin[] plugins = onGetPlugins();
            Connection.SendPacket(new MsgPluginCount(plugins.Length), PacketId.Unknown);
            foreach (IPlugin plugin in plugins)
            {
                //lets see if client is having correct version
                Connection.pluginSystem.AddPlugin(plugin, getClientsDelegate);
                plugin.onRegisterMessages(Connection.messageHandler);
                Connection.SendPacket(new MsgGetPluginInfo(plugin.PluginId), PacketId.Unknown);

                if (!Connection.Receive((IMessage message) =>
                {
                    MsgGetPluginInfoResponse response = message as MsgGetPluginInfoResponse;

                    if (response != null)
                    {
                        if (plugin.Name != response.PluginName || plugin.PluginVersion.ToString() != response.VersionString)
                            return false;
                        return true;
                    }
                    return false;
                }).Wait<bool>(false, 30000))
                {
                    Disconnect();
                    return false;
                }

                try
                {
                    if (plugin.AllowPluginHooks() && plugin.Hooks.Count > 0)
                    {
                        foreach (IPluginHook hook in plugin.Hooks)
                            hook.onClientConnected();
                    }
                }
                catch (Exception ex)
                {
                    onException(ex);
                }
                plugin.onClientConnected();
                Connection.SendPacket(new MsgInitPlugin(plugin.PluginId), PacketId.Unknown);
            }

            if (!Connection.Receive((IMessage message) =>
            {
                MsgOk msgOk = message as MsgOk;
                if (msgOk != null)
                {
                    //do here extra checks if required
                    Connection.SendPacket(new MsgOk(), PacketId.Unknown); //say its ok
                    return true;
                }
                return false;
            }).Wait<bool>(false, 30000))
            {
                Disconnect();
                return false;
            }

            this.CompletedHandshake = true;
            this.Connection.KeepAliveSW = Stopwatch.StartNew();
            return true;
        }

        internal void StartReceiver()
        {
            this.Connection.StartNetworkStream();
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
                    this.Connection.SendPacket(new MsgOpenChannel(), PacketId.OpenChannel, true);
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
                        onException(ex);
                    }
                    return ChannelError.Success;
                }
            }
            catch(Exception ex)
            {
                onException(ex);
            }
            return ChannelError.InitializeError;
        }

        private unsafe void AsyncSocketCallback(object o, SocketAsyncEventArgs e)
        {
            if (e.LastOperation == SocketAsyncOperation.ReceiveFrom)
            {
                try
                {
                    if (e.BytesTransferred >= 17)
                    {
                        //decrypt traffic here
                        PayloadReader pr = new PayloadReader(e.Buffer);
                        decimal clientId = pr.ReadDecimal();
                        UdpPAcketId packetId = (UdpPAcketId)pr.ReadByte();
                        byte[] payload = pr.ReadBytes(e.BytesTransferred - pr.Offset);

                        if (this.ClientId == clientId)
                        {
                            if (UdpHandshaked)
                            {
                                switch (packetId)
                                {
                                    case UdpPAcketId.Payload:
                                    {
                                        onReceiveUdpData(payload, payload.Length);
                                        break;
                                    }
                                }
                            }
                            else
                            {
                                if (payload.Length == this.UdpHandshakeCode.Length)
                                {
                                    fixed (byte* ptr = payload, ptr2 = this.UdpHandshakeCode)
                                    {
                                        if (NativeMethods.memcmp(ptr, ptr2, (uint)this.UdpHandshakeCode.Length) == 0)
                                        {
                                            this.UdpEndPoint = e.RemoteEndPoint as IPEndPoint;
                                            this.UdpAsyncReceiveEvent.RemoteEndPoint = this.UdpEndPoint;
                                            Connection.SendPacket(new MsgUdpValidation(new byte[] { 0x8F, 0xFF, 0x46, 0x4F, 0x37 }), PacketId.Unknown, true, true);
                                            UdpHandshaked = true;
                                            UdpSyncObject.Value = true;
                                            UdpSyncObject.Pulse();
                                        }
                                    }
                                }
                            }
                        }
                        else
                        {

                        }
                    }
                }
                catch(Exception ex)
                {
                    onException(ex);
                }

                if (!UdpHandle.ReceiveFromAsync(UdpAsyncReceiveEvent))
                    AsyncSocketCallback(null, UdpAsyncReceiveEvent);
            }
            else
            {

            }
        }

        public void Disconnect()
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
                onException(ex);
            }

            try
            {
                lock (Connection)
                {
                    if (this.Connected && !ConnectionClosedNormal)
                    {
                        Connection.SendPacket(new MsgDisconnected(), PacketId.Disconnected, true);
                        ConnectionClosedNormal = true;
                    }
                }
            }
            catch (Exception ex)
            {
                onException(ex);
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
                onException(ex);
            }

            this.State = ConnectionState.Closed;
            this.Connected = false;

            if (CompletedHandshake)
            {
                try
                {
                    onDisconnect();
                }
                catch (Exception ex)
                {
                    onException(ex);
                }
            }
        }
    }
}