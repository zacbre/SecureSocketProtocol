using SecureSocketProtocol2.Misc;
using SecureSocketProtocol2.Network.Messages;
using SecureSocketProtocol2.Network.Messages.TCP;
using SecureSocketProtocol2.Network.Messages.TCP.LiteCode;
using SecureSocketProtocol2.Network.Messages.TCP.StreamMessages;
using SecureSocketProtocol2.Network.RootSocket;
using SecureSocketProtocol2.Plugin;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace SecureSocketProtocol2.Network
{
    public sealed partial class Connection
    {
        //just some queue's to make everything more simple
        //just also incase you want to open/close channels while you're receiving data
        private TaskQueue<ChannelRecvInfo> ChannelPayloadQueue;
        private TaskQueue<IMessage> CloseChannelQueue;
        private TaskQueue<IMessage> DisconnectedQueue;
        private TaskQueue<IMessage> OpenChannelQueue;
        private TaskQueue<IMessage> ResponseQueue;
        private TaskQueue<IMessage> PacketTaskQueue;
        private TaskQueue<IMessage> PayloadQueue;
        private TaskQueue<IMessage> KeepAliveQueue;
        private TaskQueue<PluginRecvInfo> PluginDataQueue;
        private TaskQueue<IMessage> StreamQueue;
        private TaskQueue<IMessage> LiteCodeQueue;
        private TaskQueue<IMessage> LiteCodeDelegateQueue;
        private TaskQueue<IPeerMessage> RootSocketQueue;
        private TaskQueue<IMessage> RequestQueue;
        private byte[] ReceiveBuffer;

        internal bool InvokedOnDisconnect = false;

        /// <summary>
        /// Used to keep receiving data from it's destination
        /// </summary>
        internal void StartNetworkStream()
        {
            if (stream != null)
                return; //don't start the network stream twice

            this.stream = new NetworkStream(this, networkStreamCallback);
            ReceiveBuffer = new byte[70000];
            Handle.BeginReceive(ReceiveBuffer, 0, ReceiveBuffer.Length, SocketFlags.None, AsyncSocketCallback, null);
        }

        private void AsyncSocketCallback(IAsyncResult result)
        {
            int BytesTransferred = 0;
            try
            {
                BytesTransferred = Handle.EndReceive(result);
            }
            catch
            {
                
            }

            if (BytesTransferred <= 0)
            {
                try
                {
                    if (!InvokedOnDisconnect)
                    {
                        InvokedOnDisconnect = true;
                        Client.Disconnect(DisconnectReason.UnexpectedlyDisconnected);
                    }
                }
                catch (Exception ex)
                {
                    Client.onException(ex, ErrorType.Core);
                }
                return;
            }

            this.LastPacketSW = Stopwatch.StartNew();

            try
            {
                //let's check the certificate
                if (Client.Certificate.ValidFrom > (Client.ServerSided ? DateTime.Now : Client.TimeSync)) //DateTime.Now)
                {
                    //we need to wait till the time is right
                    Client.Disconnect(DisconnectReason.CertificatePastValidTime);
                    return;
                }
                if (Client.Certificate.ValidTo < (Client.ServerSided ? DateTime.Now : Client.TimeSync))//DateTime.Now)
                {
                    //certificate is not valid anymore
                    Client.Disconnect(DisconnectReason.CertificatePastValidTime);
                    return;
                }

                BytesIn += (ulong)BytesTransferred;
                //to make it 2x faster remove Array.Copy and set buffer offset in asyncReceiveEvent
                //too bad i've not acomplished this yet some really weird shit is happening then
                int writeOffset = stream.Write(ReceiveBuffer, 0, BytesTransferred);
                this.stream.Flush();

                Handle.BeginReceive(ReceiveBuffer, 0, ReceiveBuffer.Length, SocketFlags.None, AsyncSocketCallback, null);
            }
            catch (Exception ex)
            {
                /*if (Client.ServerAllowsReconnecting)
                {
                    Client.Connect(ConnectionState.Reconnecting);
                }
                else*/
                {
                    Client.Disconnect(DisconnectReason.UnexpectedlyDisconnected);
                    Client.onException(ex, ErrorType.Core);
                }
            }
        }

        private unsafe void networkStreamCallback(Network.NetworkStream stream)
        {
            lock (stream)
            {
                bool DataAvailable = true;
                while (DataAvailable)
                {
                    switch (this.stream.ReceiveState)
                    {
                        case ReceiveType.Header:
                        {
                            if (stream.CanRead(HEADER_SIZE))
                            {
                                byte[] headerData = new byte[HEADER_SIZE];
                                if (stream.Read(ref headerData, 0, headerData.Length) > 0)
                                {
                                    //wopEncryption.Decrypt(header, 0, HEADER_SIZE);
                                    stream.NetworkPayload.Header = new PacketHeader(headerData, 0, this);

                                    if (!DPI.Inspect(stream.NetworkPayload.Header))
                                    {
                                        Client.Disconnect(DisconnectReason.DeepPacketInspectionDisconnection);
                                        return;
                                    }
                                    this.stream.ReceiveState = ReceiveType.Payload;
                                }
                            }
                            else
                            {
                                DataAvailable = false;
                            }
                            break;
                        }
                        case ReceiveType.Payload:
                        {
                            if (stream.CanRead(stream.NetworkPayload.Header.PacketSize))
                            {
                                int receivedSize = stream.NetworkPayload.Header.PacketSize;
                                uint packetSize = (uint)stream.NetworkPayload.Header.PacketSize;
                                byte[] payload = stream.Buffer;
                                uint offset = (uint)stream.Position;
                                PacketHeader header = stream.NetworkPayload.Header;
                                IPlugin plugin = null;
                                uint GenHash = 0;

                                if (stream.NetworkPayload.Header.PacketID == PacketId.PluginPacket)
                                {
                                    plugin = pluginSystem.GetPlugin(stream.NetworkPayload.Header.PluginId);

                                    if (plugin == null)
                                        throw new Exception("Plugin not found");
                                }

                                if (Client.Certificate != null)
                                {
                                    GenHash = stream.NetworkPayload.Header.HashPayload(payload, (int)offset, (int)packetSize, Client.Certificate.Checksum);

                                    if (stream.NetworkPayload.Header.Hash != GenHash)
                                    {
                                        Client.Disconnect(DisconnectReason.DataModificationDetected);
                                        return;
                                    }
                                }

                                //peer code
                                if (stream.NetworkPayload.Header.PeerId != 0 && stream.NetworkPayload.Header.PacketID == PacketId.RootSocket_Payload)
                                {
                                    if (stream.NetworkPayload.Header.PeerId == Client.VirtualIpInt && !Client.ServerSided)
                                    {
                                        //we arrived at the target peer !
                                        IPeerMessage PeerMsg = null;
                                        try
                                        {
                                            PeerMsg = (IPeerMessage)messageHandler.HandleMessage(new PayloadReader(payload) { Offset = (int)offset }, stream.NetworkPayload.Header.MessageId);

                                            if (PeerMsg != null)
                                            {
                                                PeerMsg.RawSize = stream.NetworkPayload.Header.PacketSize;
                                                PeerMsg.DecompressedRawSize = payload.Length;
                                            }
                                        }
                                        catch (Exception ex)
                                        {
                                            Client.onException(ex, ErrorType.Core);
                                            return;
                                        }

                                        lock (Client.PeerConnections)
                                        {
                                            RootPeer peer = null;
                                            if (Client.PeerConnections.TryGetValue(PeerMsg.ConnectionId, out peer))
                                            {
                                                /*try
                                                {
                                                    if (!peer.DPI.Inspect(stream.NetworkPayload.Header, PeerMsg))
                                                    {
                                                        Client.Disconnect(DisconnectReason.DeepPacketInspectionDisconnection);
                                                        return;
                                                    }
                                                }
                                                catch { }*/

                                                PeerMsg.Peer = peer;
                                                RootSocketQueue.Enqueue(PeerMsg);
                                            }
                                        }
                                    }
                                    else if (Client.ServerSided)
                                    {
                                        SSPClient TargetClient = null;

                                        lock (Client.PeerConnections)
                                        {
                                            for (int i = 0; i < Client.PeerConnections.Count; i++)
                                            {
                                                RootPeer rootPeer = Client.PeerConnections.Values[i];
                                                if (rootPeer.FromClient != null && rootPeer.FromClient.VirtualIpInt == stream.NetworkPayload.Header.PeerId)
                                                {
                                                    TargetClient = rootPeer.FromClient;
                                                    break;
                                                }
                                                if (rootPeer.ToClient != null && rootPeer.ToClient.VirtualIpInt == stream.NetworkPayload.Header.PeerId)
                                                {
                                                    TargetClient = rootPeer.ToClient;
                                                    break;
                                                }
                                            }
                                        }

                                        if (TargetClient != null)
                                        {
                                            //no protection is being applied to the payload
                                            //the protection should already have been applied
                                            //when the client sended this data to the server
                                            NetworkPayloadWriter pw = new NetworkPayloadWriter(this);
                                            pw.WriteBytes(payload, (int)offset, receivedSize);
                                            TargetClient.Connection.SendPayload(pw, stream.NetworkPayload.Header.MessageId,
                                                                                PacketId.RootSocket_Payload, false, null, null,
                                                                                stream.NetworkPayload.Header.PeerId);
                                        }
                                    }
                                    else
                                    {
                                        //strange...
                                    }

                                    this.stream.ReceiveState = ReceiveType.Header;
                                    stream.Position += receivedSize;
                                    payload = null;
                                    break;
                                }

                                //decrypt, decompress, de-cache the data we received
                                if (plugin != null && plugin.UseOwnProtection)
                                {
                                    payload = plugin.protection.RemoveProtection(payload, ref offset, ref packetSize, ref stream.NetworkPayload.Header);
                                }
                                else
                                {
                                    payload = protection.RemoveProtection(payload, ref offset, ref packetSize, ref stream.NetworkPayload.Header);
                                }

                                /*
                                if (stream.NetworkPayload.isCached)
                                {
                                    payload = ReceiveCache.DeCache(payload, offset, packetSize);
                                    offset = 0;
                                    packetSize = payload.Length;
                                }*/

                                IMessage message = null;
                                try
                                {
                                    message = messageHandler.HandleMessage(new PayloadReader(payload) { Offset = (int)offset }, stream.NetworkPayload.Header.MessageId);

                                    if (message != null)
                                    {
                                        message.RawSize = stream.NetworkPayload.Header.PacketSize;
                                        message.DecompressedRawSize = payload.Length;
                                    }
                                }
                                catch (Exception ex)
                                {
                                    Client.onException(ex, ErrorType.Core);
                                    return;
                                }

                                if (!Client.DPI.Inspect(null, message))
                                {
                                    Client.Disconnect(DisconnectReason.DeepPacketInspectionDisconnection);
                                    return;
                                }

                                /*if(ProcessSpeed == ReceivePerformance.Unsafe)
                                {
                                    if(!MovedPayload && plugin != null && (plugin.UseOwnSystem))
                                    {
                                        //payload is not moved from memory and plugin is using his own system
                                        //We'll just copy the memory...
                                        payload = new byte[packetSize];
                                        fixed (byte* dataPtr = payload, streamPtr = stream.Buffer)
                                        {
                                            NativeMethods.memcpy(dataPtr, streamPtr, (uint)packetSize);
                                        }
                                    }
                                }*/

                                switch (stream.NetworkPayload.Header.PacketID)
                                {
                                    case PacketId.PacketQueue:
                                    {
                                        PacketTaskQueue.Enqueue(message);
                                        break;
                                    }
                                    case PacketId.ChannelPayload:
                                    {
                                        ChannelPayloadQueue.Enqueue(new ChannelRecvInfo(message, stream.NetworkPayload.Header.ChannelId));
                                        break;
                                    }
                                    case PacketId.CloseChannel:
                                    {
                                        CloseChannelQueue.Enqueue(message);
                                        break;
                                    }
                                    case PacketId.Disconnected:
                                    {
                                        DisconnectedQueue.Enqueue(message);
                                        break;
                                    }
                                    case PacketId.OpenChannel:
                                    {
                                        OpenChannelQueue.Enqueue(message);
                                        break;
                                    }
                                    case PacketId.OpenChannelResponse:
                                    case PacketId.LiteCodeResponse:
                                    case PacketId.KeepAlive:
                                    {
                                        ResponseQueue.Enqueue(message);
                                        break;
                                    }
                                    case PacketId.Payload:
                                    {
                                        PayloadQueue.Enqueue(message);
                                        break;
                                    }
                                    case PacketId.PluginPacket:
                                    {
                                        PluginDataQueue.Enqueue(new PluginRecvInfo(plugin, message, payload));
                                        break;
                                    }
                                    case PacketId.StreamMessages:
                                    {
                                        StreamQueue.Enqueue(message);
                                        break;
                                    }
                                    case PacketId.LiteCode:
                                    {
                                        LiteCodeQueue.Enqueue(message);
                                        break;
                                    }
                                    case PacketId.LiteCode_Delegates:
                                    {
                                        LiteCodeDelegateQueue.Enqueue(message);
                                        break;
                                    }
                                    case PacketId.RequestMessages:
                                    {
                                        RequestQueue.Enqueue(message);
                                        break;
                                    }
                                }

                                this.stream.ReceiveState = ReceiveType.Header;
                                stream.Position += receivedSize;
                                payload = null;
                            }
                            else
                            {
                                DataAvailable = false;
                            }
                            break;
                        }
                    }
                }
            }
        }

        private void onKeepAliveQueue(IMessage message)
        {
            this.KeepAliveSW = Stopwatch.StartNew();
            Client.onKeepAlive();
        }
        private void onChannelPayloadQueue(ChannelRecvInfo channelInfo)
        {
            lock (Client.channels)
            {
                Channel channel = null;
                if (Client.channels.TryGetValue(channelInfo.ChannelId, out channel))
                {
                    try
                    {
                        if (channel.State == ConnectionState.Open)
                        {
                            channel.onReceiveMessage(channelInfo.Message);
                        }
                    }
                    catch (Exception ex)
                    {
                        Client.onException(ex, ErrorType.UserLand);
                    }
                }
            }
        }
        private void onDisconnectedQueue(IMessage message)
        {
            MsgDisconnected msg = message as MsgDisconnected;
            if ((msg = message as MsgDisconnected) != null)
                msg.ProcessPayload(Client);
        }
        private void onResponseQueue(IMessage message)
        {
            if ((message as MsgOpenStreamResponse) != null ||
                (message as MsgExecuteMethodResponse) != null ||
                (message as MsgGetSharedClassResponse) != null ||
                (message as MsgKeepAlive) != null)
            {
                message.ProcessPayload(Client);
            }
        }
        private void onRequestQueue(IMessage message)
        {
            if ((message as MsgGetNextId) != null)
            {
                message.ProcessPayload(Client);
            }
        }
        private void onPluginDataQueue(PluginRecvInfo pluginInfo)
        {
            if (pluginInfo.Plugin.AllowPluginHooks() && pluginInfo.Plugin.Hooks.Count > 0)
            {
                bool Continue = true;
                foreach (IPluginHook hook in pluginInfo.Plugin.Hooks)
                {
                    IMessage message = pluginInfo.message;
                    if (!hook.onReceiveMessage(ref message))
                        Continue = false;
                    pluginInfo.message = message;
                }
                if (!Continue)
                    return;
            }
            pluginInfo.Plugin.onReceiveMessage(pluginInfo.message);
        }
        private void onPacketTaskQueue(IMessage message)
        {
            MsgPacketQueue msgPacketQueue = message as MsgPacketQueue;

            if (msgPacketQueue == null)
            {
                //client is behaving strange
                Client.Disconnect(DisconnectReason.StrangeBehaviorDetected);
                return;
            }

            PayloadReader pr = new PayloadReader(msgPacketQueue.Data);
            while (pr.Offset < pr.Length)
            {
                PacketId packetId = (PacketId)pr.ReadByte();
                byte Duplicates = pr.ReadByte();
                bool isPlugin = pr.ReadBool();

                ulong PluginId = isPlugin ? pr.ReadULong() : 0;
                bool isChannel = pr.ReadBool();

                uint ChannelConnectionId = isChannel ? pr.ReadUInteger() : 0;
                uint MessageId = pr.ReadUInteger();

                byte[] data = pr.ReadBytes(pr.ReadThreeByteInteger());
                int TotalLength = data.Length * Duplicates;

                for (; Duplicates > 0; Duplicates--)
                {
                    //read the message again in a loop just incase if somebody will change the variables in the message
                    IMessage TempMsg = messageHandler.HandleMessage(new PayloadReader(data), MessageId);

                    switch (packetId)
                    {
                        case PacketId.Payload:
                        {
                            try
                            {
                                //if(DPI.Inspect(data, false))
                                {
                                    if (Client.MultiThreadProcessing)
                                    {
                                        //ThreadPool.QueueUserWorkItem((object o) => Client.onReceiveMessage(TempMsg));
                                    }
                                    else
                                    {
                                        //Client.onReceiveMessage(TempMsg);
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                Client.onException(ex, ErrorType.UserLand);
                            }
                            break;
                        }
                        case PacketId.StreamMessages:
                        {
                            StreamQueue.Enqueue(TempMsg);
                            break;
                        }
                        case PacketId.ChannelPayload:
                        {
                            //new R_ChannelPayload(data) { RawSize = data.Length }.ReadPayload(this);
                            break;
                        }
                    }
                }
            }
        }

        private void onPayloadQueue(IMessage message)
        {
            try
            {
                if (Client.MultiThreadProcessing)
                {
                    ThreadPool.QueueUserWorkItem((object o) =>
                    {
                        IMessage msg = o as IMessage;
                        //Client.onReceiveMessage(msg);
                    }, message);
                }
                else
                {
                    //Client.onReceiveMessage(message);
                }
            }
            catch (Exception ex)
            {
                Client.onException(ex, ErrorType.UserLand);
            }
        }
        private void onStreamQueue(IMessage message)
        {
            if (message as MsgOpenStream != null || message as MsgOpenStreamResponse != null ||
                message as MsgStreamData != null || message as MsgCloseStream != null)
            {
                message.ProcessPayload(Client);
            }
        }
        private void onLiteCodeQueue(IMessage message)
        {
            if (message as MsgExecuteMethod != null || message as MsgGetSharedClass != null || message as MsgDisposeClass != null)
            {
                message.ProcessPayload(Client);
            }
        }
        private void onLiteCodeResponseQueue(IMessage message)
        {
            if (message as MsgExecuteMethodResponse != null || message as MsgGetSharedClassResponse != null)
            {
                message.ProcessPayload(Client);
            }
        }
        private void onLiteCodeDelegateQueue(IMessage message)
        {
            if (message as MsgExecuteMethod != null || message as MsgExecuteMethodResponse != null)
            {
                message.ProcessPayload(Client);
            }
        }
        private void onRootSocketQueue(IPeerMessage message)
        {
            message.Peer.onReceiveMessage(message);
        }

        internal SyncObject Receive(ReceiveCallback callback)
        {
            lock (Handle)
            {
                if (callback == null)
                    throw new ArgumentNullException("callback");

                if (!Connected)
                    return null;

                SyncObject syncObject = new SyncObject(this);
                NetworkPayload networkPayload = new NetworkPayload(this, syncObject, callback);
                SocketError error = SocketError.AccessDenied;
                Handle.BeginReceive(networkPayload.Payload, 0, (int)networkPayload.PacketSize, SocketFlags.None, out error, ReceivePayloadCallback, networkPayload);
                return syncObject;
            }
        }

        private void ReceivePayloadCallback(IAsyncResult ar)
        {
            NetworkPayload networkPayload = (NetworkPayload)ar.AsyncState;
            SocketError error = SocketError.AccessDenied;
            int received = 0;

            try
            {
                //even tho there is "out error" it can still throw a error
                received = Handle.EndReceive(ar, out error);
            }
            catch { }

            if (received <= 0 || error != SocketError.Success)
            {
                Client.Disconnect(DisconnectReason.UnexpectedlyDisconnected);
                return;
            }

            BytesIn += (ulong)received;
            this.LastPacketSW = Stopwatch.StartNew();

            networkPayload.WriteOffset += (uint)received;
            if (networkPayload.WriteOffset == networkPayload.PacketSize && networkPayload.ReceivedHeader)
            {
                uint Offset = 0;
                uint length = (uint)networkPayload.Payload.Length;

                //let's check the payload hash
                if (networkPayload.Header.Hash != networkPayload.Header.HashPayload(networkPayload.Payload, (int)Offset, (int)length, HandshakeChecksum))
                {
                    Client.Disconnect(DisconnectReason.DataModificationDetected);
                    return;
                }

                //decrypt, decompress, de-cache the data we received
                networkPayload.Payload = protection.RemoveProtection(networkPayload.Payload, ref Offset, ref length, ref networkPayload.Header);

                IMessage message = null;

                try
                {
                    message = messageHandler.HandleMessage(new PayloadReader(networkPayload.Payload), networkPayload.Header.MessageId);
                }
                catch
                {

                }

                networkPayload.syncObject.Value = networkPayload.Callback(message);
                networkPayload.syncObject.Pulse();
                return; //no need to read futher
            }

            if (!networkPayload.ReceivedHeader && networkPayload.ReceivedPacket)
            {
                try
                {
                    networkPayload.ReceivedHeader = true;
                    //wopEncryption.Decrypt(networkPayload.Payload, 0, HEADER_SIZE);
                    networkPayload.Header = new PacketHeader(networkPayload.Payload, 0, this);

                    if (!DPI.Inspect(networkPayload.Header))
                    {
                        Client.Disconnect(DisconnectReason.DeepPacketInspectionDisconnection);
                        return;
                    }

                    networkPayload.PacketSize = networkPayload.Header.PacketSize;
                    networkPayload.Payload = new byte[networkPayload.Header.PacketSize];
                    networkPayload.WriteOffset = 0; //just reset offset for reading
                }
                catch
                {
                    Client.Disconnect(DisconnectReason.UnexpectedlyDisconnected);
                    return;
                }
            }

            if (networkPayload.WriteOffset != networkPayload.PacketSize)
            {
                Handle.BeginReceive(networkPayload.Payload, (int)networkPayload.WriteOffset, (int)(networkPayload.PacketSize - networkPayload.WriteOffset), SocketFlags.None, out error, ReceivePayloadCallback, networkPayload);
            }
        }
    }
}