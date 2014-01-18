using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network
{
    public class Request
    {
        [NonSerialized]
        public SyncObject syncObject;
        public int RequestId { get; internal set; }
        public byte[] PacketData { get; set; }
        public bool SendResultBack { get; private set; }
        public object ReturnValue;

        [NonSerialized]
        public bool Async = false;

        [NonSerialized]
        public RequestCallback _Callback;

        public RequestCallback Callback
        {
            get { return _Callback; }
            private set { _Callback = value; }
        }

        public Request(Connection connection, int RequestId, byte[] data, bool SendResultBack, RequestCallback Callback = null)
        {
            this.RequestId = RequestId;
            this.syncObject = new SyncObject(connection);
            this.PacketData = data;
            this.Async = Callback != null;
            this.Callback = Callback;
            this.SendResultBack = SendResultBack;
        }

        ~Request()
        {
            syncObject = null;
            PacketData = null;
            Callback = null;
        }

        public byte[] Serialize()
        {
            try
            {
                PayloadWriter pw = new PayloadWriter();
                pw.WriteInteger(RequestId);
                pw.WriteThreeByteInteger(PacketData.Length);
                pw.WriteBytes(PacketData);
                pw.WriteByte(SendResultBack ? (byte)1 : (byte)0);
                pw.WriteObject(ReturnValue);
                return pw.ToByteArray();
            }
            catch
            {
                return null;
            }
            
        }

        public Request Deserialize(PayloadReader pr)
        {
            this.RequestId = pr.ReadInteger();
            this.PacketData = pr.ReadBytes(pr.ReadThreeByteInteger());
            this.SendResultBack = pr.ReadByte() == 1;
            this.ReturnValue = pr.ReadObject();
            return this;
        }
    }
}