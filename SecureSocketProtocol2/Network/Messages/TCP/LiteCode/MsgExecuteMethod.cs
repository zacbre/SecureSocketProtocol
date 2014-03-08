using SecureSocketProtocol2.Attributes;
using SecureSocketProtocol2.Interfaces;
using SecureSocketProtocol2.Misc;
using SecureSocketProtocol2.Plugin;
using SecureSocketProtocol2.Shared;
using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text;

namespace SecureSocketProtocol2.Network.Messages.TCP.LiteCode
{
    internal class MsgExecuteMethod : IMessage
    {
        public ReturnResult Result;
        public int RequestId;
        public byte[] Data;
        public bool RequireResultBack;

        public MsgExecuteMethod(int RequestId, byte[] Data, bool RequireResultBack)
            : base()
        {
            this.RequestId = RequestId;
            this.Data = Data;
            this.RequireResultBack = RequireResultBack;
        }
        public MsgExecuteMethod(int RequestId)
            : base()
        {
            this.RequestId = RequestId;
            this.Data = new byte[0];
        }
        public MsgExecuteMethod()
            : base()
        {

        }

        public override void ProcessPayload(IClient client, IPlugin plugin = null)
        {
            ReturnResult result = new ReturnResult(null, false);
            bool isDelegate = false;
            bool ReadFullHeader = false;
            SSPClient Client = client as SSPClient;

            try
            {
                PayloadReader pr = new PayloadReader(Data);
                int SharedClassId = pr.ReadInteger();
                int MethodId = pr.ReadInteger();
                isDelegate = pr.ReadByte() == 1;
                int DelegateId = isDelegate ? pr.ReadInteger() : 0;
                int DelegateClassId = isDelegate ? pr.ReadInteger() : 0;
                ReadFullHeader = true;

                if (Client.Connection.InitializedClasses.ContainsKey(SharedClassId))
                {
                    SharedClass sClass = Client.Connection.InitializedClasses[SharedClassId];
                    SharedMethod sharedMethod = sClass.GetMethod(MethodId);

                    if (sharedMethod != null)
                    {
                        List<object> args = new List<object>();
                        List<Type> types = new List<Type>();
                        SortedList<int, SharedDelegate> SharedDelegates = new SortedList<int, SharedDelegate>();
                        SmartSerializer serializer = new SmartSerializer();

                        lock (sharedMethod.Delegates)
                        {
                            if (sharedMethod.Delegates.ContainsKey(DelegateId))
                            {
                                for (int i = 0; i < sharedMethod.Delegates[DelegateId].sharedMethod.ArgumentTypes.Length; i++)
                                {
                                    args.Add(serializer.Deserialize(pr.ReadBytes(pr.ReadInteger())));
                                }
                            }
                            else
                            {
                                for (int i = 0; i < sharedMethod.ArgumentTypes.Length; i++)
                                {
                                    args.Add(serializer.Deserialize(pr.ReadBytes(pr.ReadInteger())));
                                }
                            }
                        }

                        if (!isDelegate) //atm no support yet for delegate inside another delegate
                        {
                            for (int i = 0; i < sharedMethod.DelegateIndex.Count; i++)
                            {
                                if (pr.ReadByte() == 1)
                                {
                                    SharedDelegate del = pr.ReadObject<SharedDelegate>();
                                    del.sharedMethod.sharedClass = sClass;
                                    args[sharedMethod.DelegateIndex.Keys[i]] = DynamicDelegateCreator.CreateDelegate(del);
                                    SharedDelegates.Add(del.sharedMethod.DelegateId, del);
                                }
                            }
                        }

                        if (isDelegate)
                        {
                            result.ReturnValue = sharedMethod.Delegates[DelegateId].Delegate.DynamicInvoke(args.ToArray());
                        }
                        else
                        {
                            MethodInfo methodInf = sClass.InitializedClass.GetType().GetMethod(sharedMethod.Name, sharedMethod.ArgumentTypes);

                            if (methodInf.GetCustomAttributes(typeof(RemoteExecutionAttribute), false).Length == 0 &&
                                methodInf.GetCustomAttributes(typeof(UncheckedRemoteExecutionAttribute), false).Length == 0)
                            {
                                //return null;
                            }
                            result.ReturnValue = methodInf.Invoke(sClass.InitializedClass, args.ToArray());
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                //if (isDelegate && ReadFullHeader)
                //    throw ex;

                result.exceptionMessage = ex.InnerException != null ? ex.InnerException.Message : ex.Message;
                result.ExceptionOccured = true;
                client.onException(ex.InnerException != null ? ex.InnerException : ex, ErrorType.UserLand);
            }

            if (RequireResultBack)
            {
                Client.Connection.SendMessage(new MsgExecuteMethodResponse(RequestId, result), PacketId.LiteCodeResponse);
            }

            base.ProcessPayload(client, plugin);
        }
    }
}