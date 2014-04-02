using SecureSocketProtocol2.Attributes;
using SecureSocketProtocol2.Interfaces;
using SecureSocketProtocol2.Misc;
using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text;

namespace SecureSocketProtocol2.Shared
{
    [Serializable]
    public class SharedClass
    {
        internal SortedList<string, List<SharedMethod>> _Methods;
        [NonSerialized]
        internal IClient Client;
        [NonSerialized]
        internal object[] BaseClassTypeArgs;
        [NonSerialized]
        internal Type BaseClassType;
        [NonSerialized]
        internal object InitializedClass;

        [NonSerialized]
        internal int SharedInitializeCounter;

        public int MaxInitializations { get; private set; }
        internal bool CanRemove { get; set; }
        public string TypeName { get; private set; }
        public string SharedName { get; private set; }
        internal int SharedId { get; set; }
        public List<Type[]> ConstructorTypes { get; private set; }
        public bool RemoteInitialize { get; private set; }
        public SharedMethod[] Methods { get; private set; }

        public bool IsDisposed { get; internal set; }

        /// <summary>  </summary>
        /// <param name="Object">The Class object to share with others</param>
        /// <param name="RemoteInitialize">False: The class will be initialized locally using the "ClassArgs" objects,
        ///                                True: The remote client will give the ClassArgs to use for initializing the object and will ignore the local argument objects</param>
        /// <param name="ClassArgs">The objects to initialize the class with</param>
        /// <param name="MaxInitializations">The maximum count that the class can be shared </param>
        internal SharedClass(string SharedName, Type ClassType, IClient Client, bool RemoteInitialize = false, int MaxInitializations = 100, params object[] ClassArgs)
        {
            if (ClassType == null)
                throw new ArgumentNullException("Object");
            if (!ClassType.IsClass)
                throw new Exception("Object is not a class");

            this._Methods = new SortedList<string, List<SharedMethod>>();
            this.BaseClassType = ClassType;
            this.BaseClassTypeArgs = ClassArgs;

            if (this.BaseClassTypeArgs == null)
                this.BaseClassTypeArgs = new object[0];

            this.TypeName = ClassType.FullName;
            this.SharedName = SharedName;
            this.Client = Client;
            this.ConstructorTypes = new List<Type[]>();
            this.RemoteInitialize = RemoteInitialize;
            this.MaxInitializations = MaxInitializations;

            List<SharedMethod> methods = new List<SharedMethod>();
            foreach (MethodInfo m in ClassType.GetMethods())
            {
                if (!m.IsPublic || m.GetCustomAttributes(typeof(RemoteExecutionAttribute), false).Length == 0
                    && m.GetCustomAttributes(typeof(UncheckedRemoteExecutionAttribute), false).Length == 0)
                {
                    continue;
                }

                SharedMethod sharedMethod = new SharedMethod(m, this);

                if (!_Methods.ContainsKey(m.Name))
                    _Methods.Add(m.Name, new List<SharedMethod>());
                _Methods[m.Name].Add(sharedMethod);

                methods.Add(sharedMethod);
                sharedMethod.MethodId = methods.Count;
            }
            this.Methods = methods.ToArray();

            foreach (ConstructorInfo m in ClassType.GetConstructors())
            {
                if (!m.IsStatic && m.IsPublic && m.GetCustomAttributes(typeof(RemoteConstructorAttribute), false).Length > 0)
                {
                    List<Type> list = new List<Type>();
                    foreach (ParameterInfo param in m.GetParameters())
                        list.Add(param.ParameterType);
                    ConstructorTypes.Add(list.ToArray());
                }
            }
        }

        ~SharedClass()
        {
            InitializedClass = null;
            SharedId = 0;
            _Methods = null;
        }

        public SharedMethod GetMethod(int methodId)
        {
            for (int i = 0; i < Methods.Length; i++)
            {
                if (Methods[i].MethodId == methodId)
                    return Methods[i];
            }
            return null;
        }

        public SharedMethod GetMethod(string MethodName, Type[] types)
        {
            if (!_Methods.ContainsKey(MethodName))
                return null;

            for (int i = 0; i < _Methods[MethodName].Count; i++)
            {
                if (_Methods[MethodName][i].ArgumentTypes.Length == types.Length)
                {
                    if (types.Length == 0)
                        return _Methods[MethodName][i];

                    for (int j = 0; j < _Methods[MethodName][i].ArgumentTypes.Length; j++)
                    {
                        if (_Methods[MethodName][i].ArgumentTypes[j].IsByRef)
                        {
                            if (j + 1 >= _Methods[MethodName][i].ArgumentTypes.Length)
                                return _Methods[MethodName][i];

                            continue; //skip this argument "out"
                        }

                        //check argument type
                        if (types[j] != null)
                        {
                            if (_Methods[MethodName][i].ArgumentTypes[j] != types[j] &&
                               _Methods[MethodName][i].ArgumentTypes[j] != types[j].BaseType)
                            {
                                break;
                            }
                        }
                        return _Methods[MethodName][i];
                    }
                }
            }
            return null;
        }

        public object Invoke(int MethodId, params object[] args)
        {
            if (IsDisposed)
                throw new Exception("The shared class is disposed");

            SharedMethod method = GetMethod(MethodId);
            lock (method.InvokeLocky)
            {
                ReturnResult ret = method.Invoke(args) as ReturnResult;

                if (ret != null)
                {
                    if (ret.ExceptionOccured)
                        throw new Exception(ret.exceptionMessage);
                    return ret.ReturnValue;
                }
                return null;
            }
            throw new Exception("Method not found");
        }
    }
}