using SecureSocketProtocol2.Attributes;
using SecureSocketProtocol2.Misc;
using SecureSocketProtocol2.Network;
using SecureSocketProtocol2.Network.Messages.TCP.LiteCode;
using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text;

namespace SecureSocketProtocol2.Shared
{
    [Serializable]
    public class SharedMethod
    {
        public string Name { get; internal set; }
        public Type[] ArgumentTypes { get; internal set; }
        public bool CanReturn { get; internal set; }
        public Type ReturnType { get; internal set; }
        internal SharedClass sharedClass;
        internal int MethodId { get; set; }
        internal object InvokeLocky = new object();
        public bool Unchecked { get; internal set; }
        public SortedList<int, SharedDelegateInfo> DelegateIndex { get; private set; }
        public SortedList<int, SharedDelegate> Delegates { get; private set; }
        public bool isDelegate { get; private set; }
        public int DelegateId { get; private set; }
        private Random rnd = new Random(new Random(DateTime.Now.Millisecond).Next());
        public bool usePacketQueue { get; private set; }
        public bool useUdp { get; private set; }
        public bool NoWaitingTime { get; private set; }
        [NonSerialized]
        private TaskQueue<object[]> MethodTaskCalls;

        internal SharedMethod(MethodInfo info, SharedClass sharedClass, bool isDelegate = false, int DelegateId = 0)
        {
            this.Name = info.Name;
            this.DelegateIndex = new SortedList<int, SharedDelegateInfo>();
            this.Delegates = new SortedList<int, SharedDelegate>();

            ParameterInfo[] parameters = info.GetParameters();
            List<Type> types = new List<Type>();
            for (int i = 0; i < parameters.Length; i++)
            {
                types.Add(parameters[i].ParameterType);

                if (parameters[i].ParameterType.BaseType != null)
                {
                    if (parameters[i].ParameterType.BaseType.FullName == "System.MulticastDelegate")
                    {
                        DelegateIndex.Add(i, new SharedDelegateInfo()
                        {
                            isUnchecked = (parameters[i].GetCustomAttributes(typeof(UncheckedRemoteExecutionAttribute), false).Length > 0),
                            UsePacketQueue = (parameters[i].GetCustomAttributes(typeof(PacketQueueAttribute), false).Length > 0),
                            UseUDP = (parameters[i].GetCustomAttributes(typeof(UdpMethodAttribute), false).Length > 0),
                            NoWaitingTime = (parameters[i].GetCustomAttributes(typeof(NoWaitMethodAttribute), false).Length > 0)
                        });
                    }
                }
            }

            this.ArgumentTypes = types.ToArray();
            this.ReturnType = info.ReturnType;
            this.Unchecked = (info.GetCustomAttributes(typeof(UncheckedRemoteExecutionAttribute), false).Length > 0);
            this.usePacketQueue = (info.GetCustomAttributes(typeof(PacketQueueAttribute), false).Length > 0);
            this.useUdp = (info.GetCustomAttributes(typeof(UdpMethodAttribute), false).Length > 0);
            this.NoWaitingTime = (info.GetCustomAttributes(typeof(NoWaitMethodAttribute), false).Length > 0);
            types.Clear();
            types = null;
            this.CanReturn = info.ReturnType.FullName != "System.Void";
            this.sharedClass = sharedClass;
            this.isDelegate = isDelegate;
            this.DelegateId = DelegateId;
        }

        ~SharedMethod()
        {
            Name = null;
            ArgumentTypes = null;
            ReturnType = null;
            sharedClass = null;
        }

        private void InvokeTask(object[] args)
        {
            object obj = null;
            _Invoke(ref obj, args);
        }

        private void _Invoke(ref object RetObject, params object[] args)
        {
            if (args.Length < ArgumentTypes.Length) //check if a argument is using "params x[] args"
                throw new Exception("missing arguments");

            List<int> usedDelegates = new List<int>();
            PayloadWriter pw = new PayloadWriter();
            pw.WriteInteger(sharedClass.SharedId);
            pw.WriteInteger(MethodId);
            pw.WriteByte(isDelegate ? (byte)1 : (byte)0);

            if (isDelegate)
            {
                pw.WriteInteger(this.DelegateId);
                pw.WriteInteger(this.sharedClass.SharedId);
            }

            SmartSerializer serializer = new SmartSerializer();
            for (int i = 0; i < args.Length; i++)
            {
                object obj = ArgumentTypes[i].IsByRef ? null : args[i];

                if (DelegateIndex.ContainsKey(i))
                    obj = null;

                byte[] SerializedObj = serializer.Serialize(obj);
                pw.WriteInteger(SerializedObj.Length);
                pw.WriteBytes(SerializedObj);
            }

            for (int i = 0; i < DelegateIndex.Count; i++)
            {
                Delegate del = args[DelegateIndex.Keys[i]] as Delegate;

                if (del != null)
                {
                    if (del.Method == null)
                        throw new Exception("Target delegate is NULL");

                    int id = rnd.Next();
                    while (Delegates.ContainsKey(id))
                        id = rnd.Next();

                    pw.WriteBool(true);
                    SharedDelegate sharedDel = new SharedDelegate(del.Method, sharedClass, del.GetType(), id, del, this.MethodId);
                    sharedDel.sharedMethod.Unchecked = this.Unchecked; //DelegateIndex.Values[i].isUnchecked;
                    sharedDel.sharedMethod.usePacketQueue = this.usePacketQueue;//DelegateIndex.Values[i].UsePacketQueue;
                    sharedDel.sharedMethod.useUdp = this.useUdp;//DelegateIndex.Values[i].UseUDP;
                    sharedDel.sharedMethod.NoWaitingTime = this.NoWaitingTime;//DelegateIndex.Values[i].NoWaitingTime;
                    pw.WriteObject(sharedDel);

                    if (!isDelegate)
                    {
                        Delegates.Add(id, sharedDel);
                    }
                    continue;
                }
                pw.WriteBool(false);
            }

            if (Unchecked || useUdp)
            {
                //just execute the method and don't wait for response
                sharedClass.Client.Connection.SendMessage(new MsgExecuteMethod(0, pw.ToByteArray(), false), isDelegate ? PacketId.LiteCode_Delegates : PacketId.LiteCode);
            }
            else
            {
                SyncObject syncObject = null;
                Random rnd = new Random();
                int RequestId = rnd.Next();
                lock (sharedClass.Client.Connection.Requests)
                {
                    while (sharedClass.Client.Connection.Requests.ContainsKey(RequestId))
                        RequestId = rnd.Next();
                    syncObject = new SyncObject(sharedClass.Client.Connection);
                    sharedClass.Client.Connection.Requests.Add(RequestId, syncObject);
                    sharedClass.Client.Connection.SendMessage(new MsgExecuteMethod(RequestId, pw.ToByteArray(), true), isDelegate ? PacketId.LiteCode_Delegates : PacketId.LiteCode);
                }
                RetObject = syncObject.Wait<ReturnResult>(null, 0);
            }

            /*if (callback != null)
            {
                sharedClass.connection.BeginSendRequest(pw, callback, true, this.usePacketQueue);
            }
            else
            {
                if (Unchecked || useUdp)
                {
                    //just don't wait till we received something back since it's a VOID anyway
                    sharedClass.connection.BeginSendRequest(pw, (object obj) => { }, false, this.usePacketQueue);
                }
                else
                {
                    RetObject = sharedClass.connection.SendRequest(pw, this.usePacketQueue);
                }
            }*/
            serializer = null;
        }

        public object Invoke(params object[] args)
        {
            object obj = null;

            if (this.NoWaitingTime)
            {
                if (this.MethodTaskCalls == null)
                    this.MethodTaskCalls = new TaskQueue<object[]>(sharedClass.Client, InvokeTask);
                this.MethodTaskCalls.Enqueue(args);
            }
            else
            {
                _Invoke(ref obj, args);
            }
            return obj;
        }

        public override string ToString()
        {
            string str = ReturnType.Name + "  " + this.Name + "(";
            for (int i = 0; i < ArgumentTypes.Length; i++)
            {
                str += ArgumentTypes[i].Name;
                if (i + 1 < ArgumentTypes.Length)
                    str += ", ";
            }
            str += ")";
            return str;
        }
    }
}
