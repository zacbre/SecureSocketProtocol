//using LiteCode.Attributes;
using System;
using System.Collections.Generic;
using System.Text;

namespace Server.LiteCode
{
    public class SharedTest : ISharedTest
    {
        public SharedTest()
        {

        }

        //[RemoteExecutionAttribute]
        public void CallTest()
        {

        }

        //[RemoteExecutionAttribute]
        public string StringTest()
        {
            return "Some random message";
        }

        //[RemoteExecutionAttribute]
        public int IntegerTest()
        {
            return 1337;
        }
    }
}
