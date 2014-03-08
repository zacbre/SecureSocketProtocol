using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Interfaces.Shared
{
    internal interface ISecureStream
    {
        void OpenStream(decimal StreamId);
        void Write(byte[] buffer, int offset, int count);
        void Close();
    }
}