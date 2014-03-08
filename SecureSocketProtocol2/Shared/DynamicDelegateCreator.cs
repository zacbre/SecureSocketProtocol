using System;
using System.Collections.Generic;
using System.Reflection;
using System.Reflection.Emit;
using System.Text;

namespace SecureSocketProtocol2.Shared
{
    internal class DynamicDelegateCreator
    {
        static object Locky = new object();
        internal static ModuleBuilder modBuilder;
        internal static string IncrementalName = " ";
        private static SortedList<int, SortedList<int, Delegate>> cache;

        static DynamicDelegateCreator()
        {
            AssemblyName assemblyName = new AssemblyName();
            assemblyName.Name = "__LiteCode__Delegates__";
            AssemblyBuilder asmBuilder = AppDomain.CurrentDomain.DefineDynamicAssembly(assemblyName, AssemblyBuilderAccess.Run);
            modBuilder = asmBuilder.DefineDynamicModule(asmBuilder.GetName().Name, true);
            cache = new SortedList<int, SortedList<int, Delegate>>();
        }

        public static Delegate CreateDelegate(SharedDelegate sharedDel)
        {
            lock (IncrementalName)
            {
                int SharedId = sharedDel.sharedMethod.sharedClass.SharedId;

                if (!cache.ContainsKey(SharedId))
                    cache.Add(SharedId, new SortedList<int, Delegate>());
                if (cache[SharedId].ContainsKey(sharedDel.sharedMethod.DelegateId))
                    return cache[SharedId][sharedDel.sharedMethod.DelegateId];

                TypeBuilder typeBuilder = modBuilder.DefineType("_Del" + IncrementName(), TypeAttributes.Public |
                                                                        TypeAttributes.Class |
                                                                        TypeAttributes.AutoClass |
                                                                        TypeAttributes.AnsiClass |
                                                                        TypeAttributes.BeforeFieldInit |
                                                                        TypeAttributes.AutoLayout |
                                                                        TypeAttributes.Sealed,
                                                                        typeof(object));

                FieldBuilder fb = typeBuilder.DefineField("$haredDelegate", typeof(SharedDelegate), FieldAttributes.Private);
                ConstructorBuilder constructor = typeBuilder.DefineConstructor(MethodAttributes.Public |
                                                                               MethodAttributes.SpecialName |
                                                                               MethodAttributes.RTSpecialName,
                                                                               CallingConventions.Standard,
                                                                               new Type[] { typeof(SharedDelegate) });

                ConstructorInfo conObj = typeof(object).GetConstructor(new Type[0]);
                ILGenerator il = constructor.GetILGenerator();
                il.Emit(OpCodes.Ldarg_0);
                il.Emit(OpCodes.Call, conObj);

                //set sharedClass variable
                il.Emit(OpCodes.Ldarg_0);
                il.Emit(OpCodes.Ldarg_1);
                il.Emit(OpCodes.Stfld, fb);
                il.Emit(OpCodes.Ret);

                string MethodName = IncrementName();
                MethodBuilder builder = typeBuilder.DefineMethod(MethodName, MethodAttributes.Public, CallingConventions.HasThis, sharedDel.sharedMethod.ReturnType, sharedDel.sharedMethod.ArgumentTypes);

                builder.CreateMethodBody(null, 0);
                ILGenerator gen = builder.GetILGenerator();

                MethodInfo SharedCall = typeof(SharedDelegate).GetMethod("Invoke");
                LocalBuilder lb = gen.DeclareLocal(typeof(object[]));

                //init local array
                gen.Emit(OpCodes.Ldc_I4, sharedDel.sharedMethod.ArgumentTypes.Length);
                gen.Emit(OpCodes.Newarr, typeof(object));
                gen.Emit(OpCodes.Stloc_0);

                for (int i = 0; i < sharedDel.sharedMethod.ArgumentTypes.Length; i++)
                {
                    gen.Emit(OpCodes.Ldloc_0);
                    gen.Emit(OpCodes.Ldc_I4, i);
                    gen.Emit(OpCodes.Ldarg, i + 1);

                    if (sharedDel.sharedMethod.ArgumentTypes[i].IsByRef)
                    {
                        //remove & at the end since ref/out adds & at the end of the argument
                        sharedDel.sharedMethod.ArgumentTypes[i] = Type.GetType(sharedDel.sharedMethod.ArgumentTypes[i].FullName.Substring(0, sharedDel.sharedMethod.ArgumentTypes[i].FullName.Length - 1));
                    }

                    gen.Emit(OpCodes.Box, sharedDel.sharedMethod.ArgumentTypes[i]);
                    gen.Emit(OpCodes.Stelem_Ref);
                }


                //load $haredDelegate
                gen.Emit(OpCodes.Ldarg_0);
                gen.Emit(OpCodes.Ldfld, fb);

                gen.Emit(OpCodes.Ldloc_0);
                gen.Emit(OpCodes.Callvirt, SharedCall);

                bool isInt = sharedDel.sharedMethod.ReturnType.IsAssignableFrom(typeof(System.Int32)) ||
                             sharedDel.sharedMethod.ReturnType.IsAssignableFrom(typeof(System.UInt32)) ||
                             sharedDel.sharedMethod.ReturnType.IsAssignableFrom(typeof(System.Boolean)) ||
                             sharedDel.sharedMethod.ReturnType.IsAssignableFrom(typeof(System.Int64)) ||
                             sharedDel.sharedMethod.ReturnType.IsAssignableFrom(typeof(System.UInt64));

                if (sharedDel.sharedMethod.ReturnType.FullName != "System.Void" && !isInt)
                {
                    gen.Emit(OpCodes.Box, sharedDel.sharedMethod.ReturnType);
                }
                else if (sharedDel.sharedMethod.ReturnType.FullName == "System.Void") //no return
                {
                    gen.Emit(OpCodes.Pop);
                }
                else if (isInt)
                {
                    gen.Emit(OpCodes.Unbox, sharedDel.sharedMethod.ReturnType);
                    gen.Emit(OpCodes.Ldobj, sharedDel.sharedMethod.ReturnType);
                }
                gen.Emit(OpCodes.Ret);

                Type InitType = typeBuilder.CreateType();
                object InitObject = InitType.GetConstructor(new Type[] { typeof(SharedDelegate) }).Invoke(new object[] { sharedDel });

                MethodInfo info = InitObject.GetType().GetMethod(MethodName);
                return Delegate.CreateDelegate(sharedDel.DelegateType, InitObject, info);
            }
        }

        private static string IncrementName()
        {
            if (IncrementalName[IncrementalName.Length - 1] == 254)
                IncrementalName += " ";
            char[] tmp = IncrementalName.ToCharArray();
            tmp[tmp.Length - 1]++;
            IncrementalName = new string(tmp);
            return IncrementalName;
        }
    }
}
