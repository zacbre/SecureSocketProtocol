using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace SecureSocketProtocol2.Network
{
    public class NetworkPayloadWriter : PayloadWriter
    {
        private int BeginPos = 0;
        public void ResetPosition()
        {
            base.vStream.Position = BeginPos;
        }

        public int PayloadSize
        {
            get
            {
                return (int)vStream.Length - BeginPos;
            }
        }

        public byte[] Buffer
        {
            get
            {
                return base.vStream.GetBuffer();
            }
        }

        /// <summary>
        /// Initialize the Network Payload Writer
        /// </summary>
        /// <param name="ExtraSize">Used to if you want for example to write your own header information</param>
        public NetworkPayloadWriter(Connection connection, int ExtraSize = 0)
            : base()
        {
            base.WriteBytes(new byte[connection.HEADER_SIZE + ExtraSize]);
            base.vStream.Position = connection.HEADER_SIZE;
            this.BeginPos = connection.HEADER_SIZE;
        }

        public byte[] GetPayload()
        {
            long pos = vStream.Position;
            ResetPosition();
            byte[] payload = new byte[vStream.Length - BeginPos];
            vStream.Read(payload, 0, payload.Length);
            vStream.Position = pos;
            return payload;
        }
    }
}