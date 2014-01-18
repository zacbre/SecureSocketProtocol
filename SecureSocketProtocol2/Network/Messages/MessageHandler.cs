﻿using SecureSocketProtocol2.Hashers;
using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages
{
    public class MessageHandler
    {
        private SortedList<uint, Type> Messages;
        internal uint Seed { get; private set; }
        private MurmurHash2Unsafe hasher;
        public MessageCache SendCache;
        public MessageCache ReceiveCache;

        public MessageHandler(int Seed)
        {
            this.SendCache = new MessageCache(this);
            this.ReceiveCache = new MessageCache(this);
            this.Messages = new SortedList<uint, Type>();
            this.hasher = new MurmurHash2Unsafe();
            this.AddMessage(typeof(MsgValidation), "HANDSHAKE_VALIDATION");
            this.AddMessage(typeof(MsgMessageSeed), "HANDSHAKE_SEED");
        }

        internal void RegisterMessages(uint Seed)
        {
            if (Seed == 0)
            {
                //generate new seed
                Random rnd = new Random(DateTime.Now.Millisecond);
                this.Seed = (uint)((double)rnd.Next() * rnd.Next(0, int.MaxValue));
            }
            else
            {
                this.Seed = Seed;
            }

            lock (Messages)
            {
                AddMessage(typeof(MsgClientInfo), "HANDSHAKE_CLIENTINFO");
                AddMessage(typeof(MsgDiffiehellman), "HANDSHAKE_DIFFIE");
                AddMessage(typeof(MsgDisconnected), "CLIENT_DISCONNECTED");
                AddMessage(typeof(MsgKeepAlive), "KEEP_ALIVE");
                AddMessage(typeof(MsgServerEncryption), "HANDSHAKE_SERVER_ENCRYPTION");
                AddMessage(typeof(MsgUdpValidation), "HANDSHAKE_UDP_VALIDATION");
                AddMessage(typeof(MsgRsaPublicKey), "HANDSHAKE_RSA_PUBLICKEY");
                AddMessage(typeof(MsgAuthenication), "HANDSHAKE_AUTHENICATION");
                AddMessage(typeof(MsgAuthenicationSuccess), "HANDSHAKE_AUTHENICATION_RESPONSE");
                AddMessage(typeof(MsgOk), "HANDSHAKE_OK");
            }
        }

        /// <summary>
        /// Add a message
        /// </summary>
        /// <param name="message">The message type to add</param>
        /// <param name="IdentifyKey">The key to identify the sending and receiving message, the identify key must be unique</param>
        /// <param name="Seed">The seed to use</param>
        public void AddMessage(Type MessageType, string IdentifyKey, uint Seed)
        {
            lock (Messages)
            {
                uint messageId = hasher.Hash(ASCIIEncoding.Unicode.GetBytes(IdentifyKey), 0);//this.Seed); Todo: need to fix seed for plugins
                if (MessageType.BaseType == null)
                    throw new Exception("IMessage is not the base type");
                if (MessageType.GetConstructor(new Type[0]) == null)
                    throw new Exception("The type must contain a constructor with no arguments");
                if (Messages.ContainsKey(messageId))
                    throw new Exception("A message with this IdentifyKey(" + IdentifyKey + ") already exists");

                Messages.Add(messageId, MessageType);
            }
        }

        /// <summary>
        /// Add a message
        /// </summary>
        /// <param name="message">The message type to add</param>
        /// <param name="IdentifyKey">The key to identify the sending and receiving message, the identify key must be unique</param>
        public void AddMessage(Type MessageType, string IdentifyKey)
        {
            AddMessage(MessageType, IdentifyKey, this.Seed);
        }

        /// <summary>
        /// Get the message id that was registered as a UINT
        /// </summary>
        /// <param name="MessageType">The message type</param>
        /// <returns>The message Id</returns>
        public uint GetMessageId(Type MessageType)
        {
            lock (Messages)
            {
                for (int i = 0; i < Messages.Count; i++)
                {
                    Type type = Messages.Values[i];
                    if (Messages.Values[i] == MessageType)
                        return Messages.Keys[i];
                }
                throw new Exception("Message Id not found, Message not registered ?");
            }
        }

        public IMessage HandleMessage(PayloadReader reader, uint MessageId)
        {
            lock (Messages)
            {
                Type type = null;
                if (!Messages.TryGetValue(MessageId, out type))
                    return null;

                IMessage message = (IMessage)Activator.CreateInstance(type, new object[0]);
                message.ReadPacket(message, reader, this);
                message.RawSize = reader.Packet.Length;
                return message;
            }
        }

        /// <summary>
        /// This method should only be called when handshake is successful
        /// </summary>
        internal void ResetMessages()
        {
            Messages.Clear();
            AddMessage(typeof(MsgOk), "HANDSHAKE_OK");
            AddMessage(typeof(MsgKeepAlive), "KEEP_ALIVE");
            AddMessage(typeof(MsgChannelPayload), "CHANNEL_PAYLOAD");
            AddMessage(typeof(MsgCloseChannel), "CHANNEL_CLOSE");
            AddMessage(typeof(MsgOpenChannel), "CHANNEL_OPEN");
            AddMessage(typeof(MsgOpenChannelResponse), "CHANNEL_OPEN_RESPONSE");
            AddMessage(typeof(MsgDisconnected), "CHANNEL_CLOSED");
            AddMessage(typeof(MsgPluginCount), "HANDSHAKE_PLUGIN_COUNT");
            AddMessage(typeof(MsgGetPluginInfo), "HANDSHAKE_GET_PLUGIN_INFO");
            AddMessage(typeof(MsgGetPluginInfoResponse), "HANDSHAKE_GET_PLUGIN_INFO_RESPONSE");
            AddMessage(typeof(MsgInitPlugin), "HANDSHAKE_GET_INIT_PLUGIN");
        }
    }
}