using SecureSocketProtocol2.Shared;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages.TCP.LiteCode
{
    internal class MsgDisposeClass : IMessage
    {
        public int SharedClassId;
        public MsgDisposeClass(int SharedClassId)
            : base()
        {
            this.SharedClassId = SharedClassId;
        }

        public MsgDisposeClass()
            : base()
        {

        }

        public override void ProcessPayload(Interfaces.IClient Client, Plugin.IPlugin plugin = null)
        {
            lock(Client.Connection.InitializedClasses)
            {
                if (Client.Connection.InitializedClasses.ContainsKey(SharedClassId))
                {
                    SharedClass initClass = Client.Connection.InitializedClasses[SharedClassId];
                    Client.Connection.InitializedClasses[SharedClassId].IsDisposed = true;

                    SharedClass localSharedClass = null;
                    lock (Client.Connection.SharedClasses)
                    {
                        if (Client.Connection.SharedClasses.TryGetValue(initClass.SharedName, out localSharedClass))
                        {
                            localSharedClass.SharedInitializeCounter--;
                        }
                    }

                    Client.Connection.InitializedClasses[SharedClassId] = null;
                    Client.Connection.InitializedClasses.Remove(SharedClassId);
                }
                else
                {
                    //strange client behavior
                    Client.Disconnect();
                }
            }
        }
    }
}