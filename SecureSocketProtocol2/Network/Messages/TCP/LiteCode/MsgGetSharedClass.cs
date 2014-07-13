using SecureSocketProtocol2.Interfaces;
using SecureSocketProtocol2.Misc;
using SecureSocketProtocol2.Plugin;
using SecureSocketProtocol2.Shared;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages.TCP.LiteCode
{
    internal class MsgGetSharedClass : IMessage
    {
        private static object Locky = new object();
        public string ClassName;
        public object[] ArgObjects;
        public int RequestId;

        public MsgGetSharedClass(string ClassName, object[] ArgObjects, int RequestId)
            : base()
        {
            this.ClassName = ClassName;
            this.ArgObjects = ArgObjects;
            this.RequestId = RequestId;
        }
        public MsgGetSharedClass()
            : base()
        {

        }

        public override void ProcessPayload(IClient client, IPlugin plugin = null)
        {
            lock (Locky)
            {
                ReturnResult result = new ReturnResult(null, false);
                SSPClient Client = client as SSPClient;
                SharedClass localSharedClass = null;

                lock (Client.Connection.SharedClasses)
                {
                    if (!Client.Connection.SharedClasses.TryGetValue(ClassName, out localSharedClass))
                    {
                        return;
                    }
                }

                try
                {
                    if (localSharedClass.RemoteInitialize)
                    {
                        bool FoundConstructor = false;

                        if (ArgObjects.Length > 0)
                        {
                            //lets check if there is a constructor with these arguments
                            for (int i = 0; i < localSharedClass.ConstructorTypes.Count; i++)
                            {
                                if (localSharedClass.ConstructorTypes[i].Length == ArgObjects.Length)
                                {
                                    bool CorrectArgs = true;
                                    for (int j = 0; j < ArgObjects.Length; j++)
                                    {
                                        if (localSharedClass.ConstructorTypes[i][j] != ArgObjects[j].GetType() &&
                                            localSharedClass.ConstructorTypes[i][j] != ArgObjects[j].GetType().BaseType)
                                        {
                                            CorrectArgs = false;
                                            break;
                                        }
                                    }

                                    if (CorrectArgs)
                                    {
                                        FoundConstructor = true;
                                        break;
                                    }
                                }
                            }
                            if (!FoundConstructor)
                                return;
                        }
                    }

                    if (localSharedClass.SharedInitializeCounter >= localSharedClass.MaxInitializations)
                    {
                        result.ExceptionOccured = true;
                        result.exceptionMessage = "Reached maximum initializations";
                    }
                    else
                    {
                        SharedClass sClass = new SharedClass(ClassName, localSharedClass.BaseClassType, Client, localSharedClass.RemoteInitialize, localSharedClass.MaxInitializations, localSharedClass.BaseClassTypeArgs);
                        sClass.InitializedClass = Activator.CreateInstance(sClass.BaseClassType, localSharedClass.RemoteInitialize ? ArgObjects : sClass.BaseClassTypeArgs);

                        int RandomId = Client.GetNextRandomInteger();
                        while (Client.Connection.InitializedClasses.ContainsKey(RandomId))
                            RandomId = Client.GetNextRandomInteger();

                        sClass.SharedId = RandomId;
                        Client.Connection.InitializedClasses.Add(RandomId, sClass);
                        result.ReturnValue = sClass;

                        localSharedClass.SharedInitializeCounter++;
                    }
                }
                catch (Exception ex)
                {
                    result.ExceptionOccured = true;
                    result.exceptionMessage = ex.InnerException != null ? ex.InnerException.Message : ex.Message;
                }
                Client.Connection.SendMessage(new MsgGetSharedClassResponse(RequestId, result), PacketId.LiteCodeResponse);
                base.ProcessPayload(client);
            }
        }
    }
}