using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Interfaces.Shared
{
    [Serializable]
    public class OpenChannelResponse
    {
        public uint ConnectionId;
        public bool success;

        public OpenChannelResponse(uint ConnectionId, bool success)
        {
            this.ConnectionId = ConnectionId;
            this.success = success;
        }
    }

    public interface ISharedChannel
    {
        void CloseChannel(ulong ConnectionId);
        void OpenChannel(Action<OpenChannelResponse> ResponseCallback);
    }
}