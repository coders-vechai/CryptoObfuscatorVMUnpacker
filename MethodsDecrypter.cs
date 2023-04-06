using System;
using System.Collections.Generic;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.IO;
using de4dot.blocks;
using System.Text;
using static System.Net.Mime.MediaTypeNames;
using System.IO;

namespace CryptoObfuscatorUnpacker
{
    class MethodsDecrypter
    {
        private readonly ModuleDefMD _module;

        public bool Detected => Type != null;
        public TypeDef Type { get; private set; }
        public EmbeddedResource Resource { get; private set; }

        public MethodsDecrypter(ModuleDefMD module) => _module = module;

        public void Find() => Type = _module.Types.FirstOrDefault(Check);

        public void Decrypt()
        {
            if (Type == null) return;
            string resName = null;
      
            var ldstrInstr = decrypterCctor.Body.Instructions.FirstOrDefault(instr => instr.OpCode == OpCodes.Ldstr);
            if (ldstrInstr != null)
            {
                resName = ldstrInstr.Operand as string;
            }

            byte[] array = Convert.FromBase64String(resName);
            resName = Encoding.UTF8.GetString(array, 0, array.Length);

            Resource = _module.Resources.OfType<EmbeddedResource>().FirstOrDefault(r => r.Name == resName);
            if (Resource == null) return;

            var decrypted = ResourceDecrypter.DecryptResource(97L, Resource.CreateReader().AsStream());
            var reader = ByteArrayDataReaderFactory.CreateReader(decrypted);

            int numEncrypted = reader.ReadInt32();
            for (int i = 0; i < numEncrypted; i++)
            {
                int delegateTypeToken = reader.ReadInt32();
                uint codeOffset = reader.ReadUInt32();
                var origOffset = reader.Position;
                reader.Position = codeOffset;
                Decrypt(ref reader, delegateTypeToken);
                reader.Position = origOffset;
            }
        }

        private bool Check(TypeDef type)
        {
            if (type.NestedTypes.Count != 1 || type.Fields.Count != 4) return false;

            var requiredFields = new[] { "System.Byte[]", "System.Collections.Generic.Dictionary`2<System.Int32,System.Int32>", "System.ModuleHandle" };
            if (!new FieldTypes(type).All(requiredFields)) return false;

            var cctor = type.FindStaticConstructor();
            if (cctor == null) return false;

            decryptMethod = FindDecryptMethod(type);
            if (decryptMethod == null) return false;

            Type = type;
            decrypterCctor = cctor;
           
            if(decrypterCctor != null)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"===>>> VM class is found!");
            }
            else 
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"===>>> Can't find VM class!"); 
            }
          
            return true;
        }

        private MethodDef decryptMethod, decrypterCctor;

        static readonly string[] RequiredLocals = new string[]
        {
            "System.Delegate",
            "System.ModuleHandle",
            "System.Reflection.Emit.DynamicILInfo",
            "System.Reflection.Emit.DynamicMethod",
            "System.Reflection.FieldInfo",
            "System.Reflection.FieldInfo[]",
            "System.Reflection.MethodBase",
            "System.Reflection.MethodBody",
            "System.Type",
            "System.Type[]"
        };

        private static MethodDef FindDecryptMethod(TypeDef type)
        {
            foreach (var method in type.Methods)
            {
                if (!method.IsStatic || method.Body == null) continue;
                if (!new LocalTypes(method).All(RequiredLocals)) continue;
                if (!DotNetUtils.IsMethod(method, "System.Void", "(System.Int32,System.Int32,System.Int32)")) continue;
                return method;
            }
            return null;
        }

        void Decrypt(ref DataReader reader, int delegateTypeToken)
        {
            var delegateType = _module.ResolveToken(delegateTypeToken) as TypeDef;
            if (delegateType == null)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"===>>> Couldn't find delegate type");
                return;
            }
            if (!GetTokens(delegateType, out int delToken, out int encMethToken, out int encDeclToken))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"===>>> Could not find encrypted method tokens");
                return;
            }

            if (delToken != delegateTypeToken)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"===>>> Invalid delegate type token");
                return;
            }

            var encType = _module.ResolveToken(encDeclToken) as ITypeDefOrRef;
            if (encType == null)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"===>>> Invalid declaring type token");
                return;
            }

            var encMethod = _module.ResolveToken(encMethToken) as MethodDef;
            if (encMethod == null)
            {
               Console.ForegroundColor = ConsoleColor.Red;
               Console.WriteLine($"===>>> Invalid encrypted method token");
                return;
            }

            var bodyReader = new MethodBodyReader(_module, ref reader);
            bodyReader.Read(encMethod);
            bodyReader.RestoreMethod(encMethod);
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"===>>> Restored method: {encMethod.FullName} {encMethod.MDToken}");
        }

        bool GetTokens(TypeDef delegateType, out int delegateToken, out int encMethodToken, out int encDeclaringTypeToken)
        {
            delegateToken = 0;
            encMethodToken = 0;
            encDeclaringTypeToken = 0;

            var cctor = delegateType.FindStaticConstructor();
            if (cctor == null) return false;

            var instrs = cctor.Body.Instructions;
            for (int i = 0; i < instrs.Count - 3; i++)
           {
                var ldci4_1 = instrs[i];
                if (!ldci4_1.IsLdcI4())
                    continue;

                var ldci4_2 = instrs[i + 1];
                if (!ldci4_2.IsLdcI4())
                    continue;

                var ldci4_3 = instrs[i + 2];
                if (!ldci4_3.IsLdcI4())
                    continue;

                var call = instrs[i + 3];
                if (call.OpCode.Code != Code.Call)
                    continue;

                var calledMethod = call.Operand as MethodDef;
                if (calledMethod == null)
                    continue;

                if (calledMethod != decryptMethod)
                    continue;

                delegateToken = ldci4_1.GetLdcI4Value();
                encMethodToken = ldci4_2.GetLdcI4Value();
                encDeclaringTypeToken = ldci4_3.GetLdcI4Value();
                return true;
            }

            return false;
        }
    }
}