using SecureSocketProtocol2.Misc;
using SecureSocketProtocol2.Plugin;
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages
{
    public class MessageCache
    {
        private SortedList<uint, IMessage> Messages;
        public MessageHandler MessageHandler { get; private set; }

        public MessageCache(MessageHandler MessageHandler)
        {
            this.Messages = new SortedList<uint, IMessage>();
            this.MessageHandler = MessageHandler;
        }

        public unsafe bool CacheMessage(NetworkPayloadWriter npw, IMessage message)
        {
            lock (Messages)
            {
                uint Id = MessageHandler.GetMessageId(message.GetType());
                IMessage CachedMessage = null;
                npw.WriteBool(false);

                if (!Messages.TryGetValue(Id, out CachedMessage))
                {
                    Messages.Add(Id, (IMessage)Activator.CreateInstance(message.GetType()));

                    FieldInfo[] tmpFields = message.GetType().GetFields();
                    for (int i = 0; i < tmpFields.Length; i++)
                    {
                        object obj = tmpFields[i].GetValue(message);
                        Type type = (obj == null ? null : obj.GetType());
                        npw.WriteObject(obj);
                    }
                    return false;
                }

                FieldInfo[] fields = message.GetType().GetFields();
                FieldInfo[] CachedFields = CachedMessage.GetType().GetFields();

                for (int i = 0; i < fields.Length; i++)
                {
                    object obj = fields[i].GetValue(message);
                    object cached = CachedFields[i].GetValue(CachedMessage);
                    Type type = (obj == null ? null : obj.GetType());
                    Type cacheType = (cached == null ? null : cached.GetType());

                    //set new value in cache
                    CachedFields[i].SetValue(CachedMessage, obj);

                    if (obj == null)
                    {
                        npw.WriteByte((byte)MessageCacheType.NULL);
                        continue;
                    }

                    MessageCacheType CacheType = MessageCacheType.NotUpdated;
                    long pos = npw.vStream.Position;
                    npw.WriteByte((byte)CacheType);

                    if (type == typeof(byte))
                    {
                        if (cached != null)
                        {
                            if ((byte)obj != (byte)cached)
                            {
                                npw.WriteByte((byte)obj);
                                CacheType = MessageCacheType.Byte;
                            }
                        }
                        else
                        {
                            npw.WriteByte((byte)obj);
                            CacheType = MessageCacheType.Byte;
                        }
                    }
                    if (type == typeof(byte[]))
                    {
                        //can be optimized ALOT by using cache for this too
                        //by only uploading the changed bytes
                        byte[] objBytes = (byte[])obj;

                        if (cached != null)
                        {
                            byte[] cachedBytes = (byte[])cached;

                            if (objBytes.Length == cachedBytes.Length)
                            {
                                fixed (byte* ptr1 = objBytes, ptr2 = cachedBytes)
                                {
                                    if (NativeMethods.memcmp(ptr1, ptr2, (uint)objBytes.Length) != 0)
                                    {
                                        CacheType = MessageCacheType.ByteArray;
                                        npw.WriteUInteger((uint)objBytes.Length);
                                        npw.WriteBytes(objBytes);
                                    }
                                }
                            }
                            else
                            {
                                CacheType = MessageCacheType.ByteArray;
                                npw.WriteUInteger((uint)objBytes.Length);
                                npw.WriteBytes(objBytes);
                            }
                        }
                        else
                        {
                            CacheType = MessageCacheType.ByteArray;
                            npw.WriteUInteger((uint)objBytes.Length);
                            npw.WriteBytes(objBytes);
                        }
                    }
                    else if (type == typeof(bool))
                    {
                        if (cached != null)
                        {
                            if ((bool)obj != (bool)cached)
                            {
                                npw.WriteBool((bool)obj);
                                CacheType = MessageCacheType.Bool;
                            }
                        }
                        else
                        {
                            npw.WriteBool((bool)obj);
                            CacheType = MessageCacheType.Bool;
                        }
                    }
                    else if (type == typeof(short))
                    {
                        if (cached != null)
                        {
                            if ((short)obj != (short)cached)
                            {
                                npw.WriteShort((short)obj);
                                CacheType = MessageCacheType.Short;
                            }
                        }
                        else
                        {
                            npw.WriteShort((short)obj);
                            CacheType = MessageCacheType.Short;
                        }
                    }
                    else if (type == typeof(ushort))
                    {
                        if (cached != null)
                        {
                            if ((ushort)obj != (ushort)cached)
                            {
                                npw.WriteUShort((ushort)obj);
                                CacheType = MessageCacheType.UShort;
                            }
                        }
                        else
                        {
                            npw.WriteUShort((ushort)obj);
                            CacheType = MessageCacheType.UShort;
                        }
                    }
                    else if (type == typeof(int))
                    {
                        if (cached != null)
                        {
                            if ((int)obj != (int)cached)
                            {
                                npw.WriteInteger((int)obj);
                                CacheType = MessageCacheType.Integer;
                            }
                        }
                        else
                        {
                            npw.WriteInteger((int)obj);
                            CacheType = MessageCacheType.Integer;
                        }
                    }
                    else if (type == typeof(uint))
                    {
                        if (cached != null)
                        {
                            if ((uint)obj != (uint)cached)
                            {
                                npw.WriteUInteger((uint)obj);
                                CacheType = MessageCacheType.UInteger;
                            }
                        }
                        else
                        {
                            npw.WriteUInteger((uint)obj);
                            CacheType = MessageCacheType.UInteger;
                        }
                    }
                    else if (type == typeof(decimal))
                    {
                        if (cached != null)
                        {
                            if ((decimal)obj != (decimal)cached)
                            {
                                npw.WriteDecimal((decimal)obj);
                                CacheType = MessageCacheType.Decimal;
                            }
                        }
                        else
                        {
                            npw.WriteDecimal((decimal)obj);
                            CacheType = MessageCacheType.Decimal;
                        }
                    }
                    else if (type == typeof(double))
                    {
                        if (cached != null)
                        {
                            if ((double)obj != (double)cached)
                            {
                                npw.WriteDouble((double)obj);
                                CacheType = MessageCacheType.Double;
                            }
                        }
                        else
                        {
                            npw.WriteDouble((double)obj);
                            CacheType = MessageCacheType.Double;
                        }
                    }
                    else if (type == typeof(float))
                    {
                        if (cached != null)
                        {
                            if ((float)obj != (float)cached)
                            {
                                npw.WriteFloat((float)obj);
                                CacheType = MessageCacheType.Float;
                            }
                        }
                        else
                        {
                            npw.WriteFloat((float)obj);
                            CacheType = MessageCacheType.Float;
                        }
                    }
                    else if (type == typeof(long))
                    {
                        if (cached != null)
                        {
                            if ((long)obj != (long)cached)
                            {
                                npw.WriteLong((long)obj);
                                CacheType = MessageCacheType.Long;
                            }
                        }
                        else
                        {
                            npw.WriteLong((long)obj);
                            CacheType = MessageCacheType.Long;
                        }
                    }
                    else if (type == typeof(ulong))
                    {
                        if (cached != null)
                        {
                            if ((ulong)obj != (ulong)cached)
                            {
                                npw.WriteULong((ulong)obj);
                                CacheType = MessageCacheType.ULong;
                            }
                        }
                        else
                        {
                            npw.WriteULong((ulong)obj);
                            CacheType = MessageCacheType.ULong;
                        }
                    }
                    else if (type == typeof(string))
                    {
                        if (cached != null)
                        {
                            if ((string)obj != (string)cached)
                            {
                                npw.WriteString((string)obj);
                                CacheType = MessageCacheType.String;
                            }
                        }
                        else
                        {
                            npw.WriteString((string)obj);
                            CacheType = MessageCacheType.String;
                        }
                    }
                    else
                    {
                        //serialize both objects and see at the bytes if they're different
                        if (cached != null)
                        {
                            using (MemoryStream ms = new MemoryStream())
                            using (MemoryStream CacheMS = new MemoryStream())
                            {
                                BinaryFormatter bf = new BinaryFormatter();
                                bf.Serialize(ms, obj);
                                bf.Serialize(CacheMS, cached);

                                if (ms.Length == CacheMS.Length)
                                {
                                    fixed (byte* ptr1 = ms.GetBuffer(), ptr2 = CacheMS.GetBuffer())
                                    {
                                        if (NativeMethods.memcmp(ptr1, ptr2, (uint)ms.Length) != 0)
                                        {
                                            CacheType = MessageCacheType.OtherObject;
                                            npw.WriteObject(obj);
                                        }
                                    }
                                }
                                else
                                {
                                    CacheType = MessageCacheType.OtherObject;
                                    npw.WriteObject(obj);
                                }
                            }
                        }
                        else
                        {
                            CacheType = MessageCacheType.OtherObject;
                            npw.WriteObject(obj);
                        }
                    }

                    if (CacheType != MessageCacheType.NotUpdated)
                    {
                        long oldPos = npw.vStream.Position;
                        npw.vStream.Position = pos;
                        npw.WriteByte((byte)CacheType);
                        npw.vStream.Position = oldPos; //jump back where we left
                    }
                }

                npw.ResetPosition();
                npw.WriteBool(true); //cached=true
                return true;
            }
        }

        public IMessage DeCacheMessage(IMessage message, PayloadReader pr, ref bool isCached, ref IMessage CachedMessage, MessageHandler msgHandler)
        {
            lock (Messages)
            {
                uint Id = msgHandler.GetMessageId(message.GetType());
                isCached = pr.ReadBool();

                if (!Messages.TryGetValue(Id, out CachedMessage) && !isCached)
                {
                    CachedMessage = (IMessage)Activator.CreateInstance(message.GetType());
                    Messages.Add(Id, (IMessage)Activator.CreateInstance(message.GetType()));

                    FieldInfo[] _fields = message.GetType().GetFields();
                    FieldInfo[] _cachedFields = CachedMessage.GetType().GetFields();

                    for (int i = 0; i < _fields.Length; i++)
                    {
                        //de-serialize objects
                        int oldPos = pr.Offset;
                        _fields[i].SetValue(message, pr.ReadObject());
                        pr.Offset = oldPos;
                        _fields[i].SetValue(Messages[Id], pr.ReadObject());
                    }
                    return message;
                }

                FieldInfo[] fields = message.GetType().GetFields();
                FieldInfo[] cacheFields = CachedMessage.GetType().GetFields();

                for (int i = 0; i < fields.Length; i++)
                {
                    MessageCacheType CacheType = (MessageCacheType)pr.ReadByte();
                    object NewValue = null;

                    switch (CacheType)
                    {
                        case MessageCacheType.Bool:
                        {
                            NewValue = pr.ReadBool();
                            break;
                        }
                        case MessageCacheType.Byte:
                        {
                            NewValue = pr.ReadByte();
                            break;
                        }
                        case MessageCacheType.ByteArray:
                        {
                            uint size = pr.ReadUInteger();
                            NewValue = pr.ReadBytes((int)size);
                            break;
                        }
                        case MessageCacheType.Decimal:
                        {
                            NewValue = pr.ReadDecimal();
                            break;
                        }
                        case MessageCacheType.Double:
                        {
                            NewValue = pr.ReadDouble();
                            break;
                        }
                        case MessageCacheType.Float:
                        {
                            NewValue = pr.ReadFloat();
                            break;
                        }
                        case MessageCacheType.Long:
                        {
                            NewValue = pr.ReadLong();
                            break;
                        }
                        case MessageCacheType.NULL:
                        {
                            NewValue = null;
                            break;
                        }
                        case MessageCacheType.OtherObject:
                        {
                            NewValue = pr.ReadObject();
                            break;
                        }
                        case MessageCacheType.Short:
                        {
                            NewValue = pr.ReadShort();
                            break;
                        }
                        case MessageCacheType.String:
                        {
                            NewValue = pr.ReadString();
                            break;
                        }
                        case MessageCacheType.Integer:
                        {
                            NewValue = pr.ReadInteger();
                            break;
                        }
                        case MessageCacheType.UInteger:
                        {
                            NewValue = pr.ReadUInteger();
                            break;
                        }
                        case MessageCacheType.ULong:
                        {
                            NewValue = pr.ReadULong();
                            break;
                        }
                        case MessageCacheType.UShort:
                        {
                            NewValue = pr.ReadUShort();
                            break;
                        }
                        case MessageCacheType.NotUpdated:
                        {
                            NewValue = cacheFields[i].GetValue(CachedMessage);
                            break;
                        }
                    }
                    fields[i].SetValue(message, NewValue);
                }
            }
            return message;
        }
    }
}