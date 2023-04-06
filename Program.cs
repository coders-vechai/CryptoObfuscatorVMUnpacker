using dnlib.DotNet;
using dnlib.DotNet.Writer;
using System.IO;
using System;
namespace CryptoObfuscatorUnpacker
{
    internal class Program
    {
        public static ModuleDefMD _module;
        static void Main(string[] args)
        {
            _module = ModuleDefMD.Load(args[0]);
         
            MethodsDecrypter methodsDecrypter = new MethodsDecrypter(_module);
            methodsDecrypter.Find();
            methodsDecrypter.Decrypt();
         
            var filePath = Path.GetDirectoryName(_module.Location);
            var fileName = Path.GetFileNameWithoutExtension(_module.Location);
            var newName = $"{fileName}-unpacked{Path.GetExtension(_module.Location)}";

            _module.Write(Path.Combine(filePath, newName), new ModuleWriterOptions(_module)
            {
                MetadataOptions = { Flags = MetadataFlags.PreserveAll },
                MetadataLogger = DummyLogger.NoThrowInstance
            });
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"===>>> File saved in: {Path.Combine(filePath, newName)}");
            Console.ReadKey();
        }
    }
}
