using System;
using System.Collections.Generic;
using System.Reflection;
using System.Reflection.Emit;
using System.Text;

namespace SecureSocketProtocol2.Shared
{
    internal class DynamicClassCreator
    {
        static object Locky = new object();
        internal static SortedList<string, Type> TypeCache;
        internal static ModuleBuilder modBuilder;

        static DynamicClassCreator()
        {
            AssemblyName assemblyName = new AssemblyName();
            assemblyName.Name = "__LiteCode__";
            AssemblyBuilder asmBuilder = AppDomain.CurrentDomain.DefineDynamicAssembly(assemblyName, AssemblyBuilderAccess.Run);
            modBuilder = asmBuilder.DefineDynamicModule(asmBuilder.GetName().Name, true);
            TypeCache = new SortedList<string, Type>();
        }

        /// <summary>
        /// Get the shared class from the remote client to call methods at the remote client
        /// </summary>
        /// <param name="classType">The main Type to use</param>
        /// <param name="InterfacePrototype">This interface should contain all the methods used in the ClassType</param>
        /// <returns>return Shared Class</returns>
        public static InterfacePrototype CreateDynamicClass<InterfacePrototype>(SharedClass sharedClass)
        {
            lock (Locky)
            {
                Type prototype = typeof(InterfacePrototype);
                if (!prototype.IsInterface || !prototype.IsPublic)
                    throw new Exception("InterfacePrototype must be a interface and public");

                if (!TypeCache.ContainsKey(prototype.FullName))
                {
                    TypeBuilder typeBuilder = modBuilder.DefineType("dyn_" + prototype.Name, TypeAttributes.Public |
                                                                                             TypeAttributes.Class |
                                                                                             TypeAttributes.AutoClass |
                                                                                             TypeAttributes.AnsiClass |
                                                                                             TypeAttributes.BeforeFieldInit |
                                                                                             TypeAttributes.AutoLayout,
                                                                                             typeof(object),
                                                                                             new Type[] { prototype });

                    //add our RootSocket info, I did on purpose "$" so u can't directly access this variable
                    FieldBuilder fb = typeBuilder.DefineField("$haredClass", typeof(SharedClass), FieldAttributes.Private);

                    DuplicateMethods(typeBuilder, prototype, fb, sharedClass);
                    CreateConstructor(typeBuilder, fb);
                    CreateDeconstructor(typeBuilder, fb);

                    Type InitType = typeBuilder.CreateType();
                    TypeCache.Add(prototype.FullName, InitType);
                    return (InterfacePrototype)InitType.GetConstructor(new Type[] { typeof(SharedClass) }).Invoke(new object[] { sharedClass });
                }
                else
                {
                    return (InterfacePrototype)TypeCache[prototype.FullName].GetConstructor(new Type[] { typeof(SharedClass) }).Invoke(new object[] { sharedClass });
                }
            }
        }

        private static ConstructorBuilder CreateConstructor(TypeBuilder typeBuilder, FieldBuilder fb)
        {
            ConstructorBuilder constructor = typeBuilder.DefineConstructor(MethodAttributes.Public | MethodAttributes.SpecialName | MethodAttributes.RTSpecialName, CallingConventions.Standard, new Type[] { typeof(SharedClass) });
            ConstructorInfo conObj = typeof(object).GetConstructor(new Type[0]);
            ILGenerator il = constructor.GetILGenerator();
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Call, conObj);

            //set sharedClass variable
            il.Emit(OpCodes.Ldarg_0);
            il.Emit(OpCodes.Ldarg_1);
            il.Emit(OpCodes.Stfld, fb);
            il.Emit(OpCodes.Ret);
            return constructor;
        }

        private static void CreateDeconstructor(TypeBuilder typeBuilder, FieldBuilder fb)
        {
            MethodBuilder mb = typeBuilder.DefineMethod("Finalize", MethodAttributes.Private, Type.GetType("System.Void"), new Type[0]);
            ILGenerator gen = mb.GetILGenerator();
            gen.Emit(OpCodes.Pop);
            gen.Emit(OpCodes.Call);
            gen.Emit(OpCodes.Ret);
        }

        private static void DuplicateMethods(TypeBuilder typeBuilder, Type target, FieldBuilder fb, SharedClass sharedClass)
        {
            foreach (MethodInfo m in target.GetMethods())
            {
                /*if ((m.GetCustomAttributes(typeof(RemoteExecutionAttribute), false).Length == 0 &&
                    m.GetCustomAttributes(typeof(UncheckedRemoteExecutionAttribute), false).Length == 0) &&
                    m.Name != "Dispose")
                {
                    continue;
                }*/

                Type[] ArgumentTypes = GetParameterTypes(m.GetParameters());
                MethodBuilder builder = typeBuilder.DefineMethod(m.Name, MethodAttributes.Public | MethodAttributes.Virtual | MethodAttributes.HideBySig, m.CallingConvention, m.ReturnType, ArgumentTypes);
                typeBuilder.DefineMethodOverride(builder, m);

                //builder.CreateMethodBody(null, 0);
                ILGenerator gen = builder.GetILGenerator();

                MethodInfo SharedCall = typeof(SharedClass).GetMethod("Invoke", new Type[] { typeof(int), typeof(object[]) });
                SharedMethod sharedMethod = sharedClass.GetMethod(m.Name, ArgumentTypes);
                LocalBuilder lb = gen.DeclareLocal(typeof(object[]));

                if (sharedMethod == null)
                    throw new Exception("Missing a method \"" + m.Name + "\" check your shared class!");

                //load $haredClass
                gen.Emit(OpCodes.Ldarg_0);
                gen.Emit(OpCodes.Ldfld, fb);

                gen.Emit(OpCodes.Ldc_I4, sharedMethod.MethodId);
                //gen.Emit(OpCodes.Ldstr, m.Name);

                //init local array
                gen.Emit(OpCodes.Ldc_I4, ArgumentTypes.Length);
                gen.Emit(OpCodes.Newarr, typeof(object));
                gen.Emit(OpCodes.Stloc_0);

                for (int i = 0; i < ArgumentTypes.Length; i++)
                {
                    gen.Emit(OpCodes.Ldloc_0);
                    gen.Emit(OpCodes.Ldc_I4, i);
                    gen.Emit(OpCodes.Ldarg, i + 1);

                    if (ArgumentTypes[i].IsByRef)
                    {
                        //remove & at the end since ref/out adds & at the end of the argument
                        ArgumentTypes[i] = Type.GetType(ArgumentTypes[i].FullName.Substring(0, ArgumentTypes[i].FullName.Length - 1));
                    }

                    gen.Emit(OpCodes.Box, ArgumentTypes[i]);
                    gen.Emit(OpCodes.Stelem_Ref);
                }

                gen.Emit(OpCodes.Ldloc_0);
                gen.Emit(OpCodes.Callvirt, SharedCall);

                bool isInt = m.ReturnType.IsAssignableFrom(typeof(System.Int32)) ||
                             m.ReturnType.IsAssignableFrom(typeof(System.UInt32)) ||
                             m.ReturnType.IsAssignableFrom(typeof(System.Boolean)) ||
                             m.ReturnType.IsAssignableFrom(typeof(System.Int64)) ||
                             m.ReturnType.IsAssignableFrom(typeof(System.UInt64));

                if (m.ReturnType.FullName != "System.Void" && !isInt)
                {
                    gen.Emit(OpCodes.Box, m.ReturnType);
                }
                else if (m.ReturnType.FullName == "System.Void") //no return
                {
                    gen.Emit(OpCodes.Pop);
                }
                else if (isInt)
                {
                    gen.Emit(OpCodes.Unbox, m.ReturnType);
                    gen.Emit(OpCodes.Ldobj, m.ReturnType);
                }
                gen.Emit(OpCodes.Ret);
            }
        }

        private static Type[] GetParameterTypes(ParameterInfo[] parameters)
        {
            List<Type> args = new List<Type>();
            foreach (ParameterInfo param in parameters)
                args.Add(param.ParameterType);
            return args.ToArray();
        }
    }
}