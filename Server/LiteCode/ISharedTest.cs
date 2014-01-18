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
    }
}