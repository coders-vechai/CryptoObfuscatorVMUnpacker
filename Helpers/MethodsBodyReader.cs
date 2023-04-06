using System.Collections.Generic;
using dnlib.IO;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
namespace CryptoObfuscatorUnpacker
{
    class MethodBodyReader : MethodBodyReaderBase
    {
        ModuleDefMD module;
        ushort maxStackSize;
        GenericParamContext gpContext;

        public MethodBodyReader(ModuleDefMD module, ref DataReader reader) : base(reader) => this.module = module;

        public void Read(MethodDef method)
        {
            gpContext = GenericParamContext.Create(method);
            parameters = method.Parameters;
            SetLocals(GetLocals(method));

            maxStackSize = (ushort)reader.ReadInt32();
            ReadInstructionsNumBytes(reader.ReadUInt32());
            ReadExceptionHandlers();
        }

        void ReadExceptionHandlers()
        {
            int totalSize = reader.ReadInt32();
            if (totalSize == 0)
                return;
            reader.ReadInt32();
            ReadExceptionHandlers((totalSize - 4) / 24);
        }

        static IList<Local> GetLocals(MethodDef method)
        {
            if (method.Body == null)
                return new List<Local>();
            return method.Body.Variables;
        }

        protected override IField ReadInlineField(Instruction instr) => module.ResolveToken(reader.ReadUInt32(), gpContext) as IField;
        protected override IMethod ReadInlineMethod(Instruction instr) => module.ResolveToken(reader.ReadUInt32(), gpContext) as IMethod;

        protected override MethodSig ReadInlineSig(Instruction instr)
        {
            var sas = module.ResolveStandAloneSig(MDToken.ToRID(reader.ReadUInt32()), gpContext);
            return sas?.MethodSig;
        }

        protected override string ReadInlineString(Instruction instr) => module.ReadUserString(reader.ReadUInt32());
        protected override ITokenOperand ReadInlineTok(Instruction instr) => module.ResolveToken(reader.ReadUInt32(), gpContext) as ITokenOperand;
        protected override ITypeDefOrRef ReadInlineType(Instruction instr) => module.ResolveToken(reader.ReadUInt32(), gpContext) as ITypeDefOrRef;

        void ReadExceptionHandlers(int numExceptionHandlers)
        {
            exceptionHandlers = new ExceptionHandler[numExceptionHandlers];
            for (int i = 0; i < exceptionHandlers.Count; i++)
                exceptionHandlers[i] = ReadExceptionHandler();
        }

        ExceptionHandler ReadExceptionHandler()
        {
            var eh = new ExceptionHandler((ExceptionHandlerType)reader.ReadUInt32());

            uint tryOffset = reader.ReadUInt32();
            eh.TryStart = GetInstructionThrow(tryOffset);
            eh.TryEnd = GetInstruction(tryOffset + reader.ReadUInt32());

            uint handlerOffset = reader.ReadUInt32();
            eh.HandlerStart = GetInstructionThrow(handlerOffset);
            eh.HandlerEnd = GetInstruction(handlerOffset + reader.ReadUInt32());

            switch (eh.HandlerType)
            {
                case ExceptionHandlerType.Catch:
                    eh.CatchType = module.ResolveToken(reader.ReadUInt32(), gpContext) as ITypeDefOrRef;
                    break;

                case ExceptionHandlerType.Filter:
                    eh.FilterStart = GetInstructionThrow(reader.ReadUInt32());
                    break;

                case ExceptionHandlerType.Finally:
                case ExceptionHandlerType.Fault:
                default:
                    reader.ReadUInt32();
                    break;
            }

            return eh;
        }

        public override void RestoreMethod(MethodDef method)
        {
            base.RestoreMethod(method);
            method.Body.MaxStack = maxStackSize;
        }
    }
}
