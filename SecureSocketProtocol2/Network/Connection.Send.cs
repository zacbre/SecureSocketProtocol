using SecureSocketProtocol2.Network.Messages;
using SecureSocketProtocol2.Plugin;
using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace SecureSocketProtocol2.Network
{
    public sealed partial class Connection
    {
        /// <summary>
        /// Sending a message by using the Packet Queue
        /// </summary>
        /// <param name="message">The message you want to send</param>
        /// <param name="packetId">The message type</param>
        /// <param name="plugin">The plugin that was used</param>
        internal void SendMessageQueue(IMessage message, PacketId packetId, IPlugin plugin = null, Channel channel = null)
        {
            if (!Client.Handshaked)
                throw new Exception("Only when the handshake is completed you're able to send a Message Queue");

            lock (Client)
            {
                packetQueue.QueuePacket(message, packetId, plugin, channel);
            }
        }

        internal void SendMessage(IMessage message, PacketId packetId, Channel channel = null)
        {
            lock (Client)
            {
                //clear the packet queue by sending all the stuff that had to be sended
                packetQueue.CleanQueue();
                SendPayload(message, packetId, null, channel);
            }
        }

        internal unsafe void SendPayload(IMessage message, PacketId packetId, IPlugin plugin = null, Channel channel = null)
        {
            NetworkPayloadWriter temp = message.WritePacket(message, this);
            message.RawSize = temp.Length - HEADER_SIZE;
            SendPayload(temp, messageHandler.GetMessageId(message.GetType()), packetId, plugin, channel);
        }

        internal unsafe void SendPayload(NetworkPayloadWriter npw, uint MessageId, PacketId packetId, IPlugin plugin = null, Channel channel = null)
        {
            SendPayload(npw, MessageId, packetId, true, plugin, channel);
        }

        /// <summary>
        /// Send the data to the target connection
        /// </summary>
        /// <param name="npw"></param>
        /// <param name="MessageId"></param>
        /// <param name="packetId"></param>
        /// <param name="ApplyProtection">Only set this to false when it's being redirected to a Peer when encryption is still applied</param>
        /// <param name="plugin"></param>
        /// <param name="channel"></param>
        internal unsafe void SendPayload(NetworkPayloadWriter npw, uint MessageId, PacketId packetId,
                                         bool ApplyProtection, IPlugin plugin = null, Channel channel = null, uint VirtualIp = 0)
        {
            lock (ClientSendLock)
            {
                while (Client.State == ConnectionState.Reconnecting)
                    Thread.Sleep(100); //wait till we are re connected
                if (Client.State != ConnectionState.Open)
                    return;

                PacketHeader header = new PacketHeader(this);
                uint offset = (uint)HEADER_SIZE;
                uint PayloadLength = (uint)npw.PayloadSize;
                byte[] payload = npw.GetBuffer();

                if (ApplyProtection)
                {
                    //apply the encryption(s), compression(s) and cache
                    /*if(plugin != null)
                        plugin.protection.ApplyProtection(npw.GetBuffer(), offset, ref length, ref header);
                    else*/
                    payload = protection.ApplyProtection(payload, ref offset, ref PayloadLength, ref header);
                }

                header.PacketSize = (int)PayloadLength;
                header.PacketID = packetId;
                header.ChannelId = channel != null ? channel.ConnectionId : 0;
                header.PeerId = VirtualIp;

                if (packetId == PacketId.PluginPacket)
                {
                    header.isPluginPacket = true;
                    if (plugin != null)
                    {
                        header.PluginId = plugin.PluginId;
                    }
                }

                header.CurPacketId = CurPacketId;
                CurPacketId++;
                header.MessageId = MessageId;
                npw.vStream.Position = 0;

                try
                {
                    header.WriteHeader(payload, (int)offset, (int)PayloadLength, npw);
                }
                catch { }
                //let's not re-write to NPW when nothing has modified
                if (protection.LayerCount > 0 && ApplyProtection)
                {
                    npw.WriteBytes(payload, (int)offset, (int)PayloadLength);
                }

                //encrypt the header
                /*wopEncryption.Encrypt(temp, 0, HEADER_SIZE);
                if (this.EncryptionType == EncryptionType.Wop)
                {
                    wopEncryption.Encrypt(temp, HEADER_SIZE, npw.Length);
                }
                else if (this.EncryptionType == EncryptionType.UnsafeXor)
                {
                    unsafeXorEncryption.Encrypt(ref temp, HEADER_SIZE, npw.Length);
                }*/

                try
                {
                    this.Handle.Send(npw.GetBuffer(), (int)PayloadLength + HEADER_SIZE, SocketFlags.None);
                    BytesOut += (ulong)(PayloadLength + HEADER_SIZE);
                }
                catch { }
            }
        }
    }
}