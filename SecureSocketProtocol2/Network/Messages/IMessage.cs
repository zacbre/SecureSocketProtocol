using SecureSocketProtocol2.Interfaces;
using SecureSocketProtocol2.Misc;
using SecureSocketProtocol2.Plugin;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Reflection;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages
{
    public abstract class IMessage
    {
        /// <summary> This is the message in raw size we received </summary>
        public int RawSize { get; set; }

        /// <summary> This is the message in raw size after decompression </summary>
        public int DecompressedRawSize { get; set; }

        public IMessage()
        {

        }

        public virtual void WritePayload(IClient client, IPlugin plugin = null)
        {

        }

        public virtual void ProcessPayload(IClient client, IPlugin plugin = null)
        {

        }

        public NetworkPayloadWriter WritePacket(IMessage message, Connection connection)
        {
            NetworkPayloadWriter npw = new NetworkPayloadWriter(connection);
            WritePacket(message, npw);
            return npw;
        }

        public void WritePacket(IMessage message, NetworkPayloadWriter npw)
        {
            //if (connection.messageHandler.SendCache.CacheMessage(npw, message))
            //    return;

            FieldInfo[] fields = message.GetType().GetFields();
            for (int i = 0; i < fields.Length; i++)
            {
                object obj = fields[i].GetValue(message);
                Type type = (obj == null ? null : obj.GetType());
                npw.WriteObject(obj);
            }
        }

        public void WritePacket(IMessage message, ref PayloadWriter pw)
        {
            FieldInfo[] fields = message.GetType().GetFields();

            for (int i = 0; i < fields.Length; i++)
            {
                object obj = fields[i].GetValue(message);
                Type type = (obj == null ? null : obj.GetType());
                pw.WriteObject(obj);
            }
        }

        public void ReadUdpPacket(IMessage message, PayloadReader pr)
        {
            FieldInfo[] fields = message.GetType().GetFields();

            for (int i = 0; i < fields.Length; i++)
            {
                fields[i].SetValue(message, pr.ReadObject());
            }
        }

        public void ReadPacket(IMessage message, PayloadReader pr, MessageHandler handler)
        {
            bool isCached = false;
            IMessage CachedMsg = null;
            //handler.ReceiveCache.DeCacheMessage(message, pr, ref isCached, ref CachedMsg, handler);

            //pr.ReadBool();
            //if (!isCached && CachedMsg != null)
            {
                FieldInfo[] fields = message.GetType().GetFields();
                //FieldInfo[] cachedFields = CachedMsg.GetType().GetFields();

                for (int i = 0; i < fields.Length; i++)
                {
                    //de-serialize objects
                    fields[i].SetValue(message, pr.ReadObject());
                }
            }
        }
    }
}