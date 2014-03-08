using SecureSocketProtocol2;
using System;
using System.Collections.Generic;
using System.Text;

namespace Server.LiteCode
{
    public interface ISharedTest
    {
        void CallTest();
        string StringTest();
        int IntegerTest();
        byte[] ByteArrayTest();
        void SecretShit();
        void DelegateTest(Callback<string> Delly);
        void SendByteArray(byte[] data);
    }
}