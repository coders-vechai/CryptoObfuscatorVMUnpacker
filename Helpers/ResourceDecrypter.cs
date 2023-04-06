using System.Globalization;
using System.IO.Compression;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System;
namespace CryptoObfuscatorUnpacker
{
    public class ResourceDecrypter
    {
        private static string GetAssemblyFullName(Assembly assembly)
        {
            string fullName = assembly.FullName;
            int index = fullName.IndexOf(',');
            if (index >= 0)
            {
                fullName = fullName.Substring(0, index);
            }
            return fullName;
        }

        private static byte[] GetPublicKeyToken(Assembly assembly)
        {
            try
            {
                string fullName = assembly.FullName;
                int index = fullName.IndexOf("PublicKeyToken=");
                if (index < 0)
                {
                    index = fullName.IndexOf("publickeytoken=");
                }
                if (index < 0)
                {
                    return null;
                }
                index += 15;
                if (fullName[index] == 'n' || fullName[index] == 'N')
                {
                    return null;
                }
                string tokenString = fullName.Substring(index, 16);
                long publicKeyToken = long.Parse(tokenString, NumberStyles.HexNumber);
                byte[] bytes = BitConverter.GetBytes(publicKeyToken);
                Array.Reverse(bytes);
                return bytes;
            }
            catch
            {
            }
            return null;
        }

        internal static byte[] DecryptStream(Stream stream)
        {
            byte[] result;
            lock (lockObject)
            {
                result = DecryptDataWithKey(97L, stream);
            }
            return result;
        }

        public static byte[] DecryptResource(long key, Stream dataStream)
        {
            byte[] result;
            try
            {
                result = DecryptStream(dataStream);
            }
            catch
            {
                result = DecryptDataWithKey(97L, dataStream);
            }
            return result;
        }

        internal static byte[] DecryptDataWithKey(long key, object data)
        {
            Stream stream = data as Stream;
            Stream inputStream = stream;
            MemoryStream memoryStream = null;
            for (int i = 1; i < 4; i++)
            {
                stream.ReadByte();
            }
            ushort num = (ushort)stream.ReadByte();
            num = (ushort)~num;
            if ((num & 2) != 0)
            {
                DESCryptoServiceProvider provider = new DESCryptoServiceProvider();
                byte[] iv = new byte[8];
                stream.Read(iv, 0, 8);
                provider.IV = iv;
                byte[] keyBytes = new byte[8];
                stream.Read(keyBytes, 0, 8);
                bool isZero = true;
                foreach (byte b in keyBytes)
                {
                    if (b != 0)
                    {
                        isZero = false;
                        break;
                    }
                }
                if (isZero)
                {
                    keyBytes = GetPublicKeyToken(Assembly.GetExecutingAssembly());
                }
                provider.Key = keyBytes;
                if (syncObject == null)
                {
                    if (maxBufferSize == int.MaxValue)
                    {
                        syncObject.Capacity = (int)stream.Length;
                    }
                    else
                    {
                        syncObject.Capacity = maxBufferSize;
                    }
                }
                syncObject.Position = 0L;
                ICryptoTransform transform = provider.CreateDecryptor();
                int inputBlockSize = transform.InputBlockSize;
                int outputBlockSize = transform.OutputBlockSize;
                byte[] outputBuffer = new byte[transform.OutputBlockSize];
                byte[] inputBuffer = new byte[transform.InputBlockSize];
                int position = (int)stream.Position;
                while ((long)(position + inputBlockSize) < stream.Length)
                {
                    stream.Read(inputBuffer, 0, inputBlockSize);
                    int num2 = transform.TransformBlock(inputBuffer, 0, inputBlockSize, outputBuffer, 0);
                    syncObject.Write(outputBuffer, 0, num2);
                    position += inputBlockSize;
                }
                stream.Read(inputBuffer, 0, (int)(stream.Length - (long)position));
                byte[] finalBuffer = transform.TransformFinalBlock(inputBuffer, 0, (int)(stream.Length - (long)position));
                syncObject.Write(finalBuffer, 0, finalBuffer.Length);
                inputStream = syncObject;
                inputStream.Position = 0L;
                memoryStream = syncObject;
            }
            if ((num & 8) != 0)
            {
                if (compressedData == null)
                {
                    if (maxDecompressedDataSize == int.MinValue)
                    {
                        compressedData.Capacity = (int)inputStream.Length * 2;
                    }
                    else
                    {
                        compressedData.Capacity = maxDecompressedDataSize;
                    }
                }
                compressedData.Position = 0L;
                DeflateStream deflateStream = new DeflateStream(inputStream, CompressionMode.Decompress);
                int bufferSize = 1000;
                byte[] buffer = new byte[bufferSize];
                int bytesRead;
                do
                {
                    bytesRead = deflateStream.Read(buffer, 0, bufferSize);
                    if (bytesRead > 0)
                    {
                        compressedData.Write(buffer, 0, bytesRead);
                    }
                }
                while (bytesRead >= bufferSize);
                memoryStream = compressedData;
            }
            if (memoryStream != null)
            {
                return memoryStream.ToArray();
            }
            byte[] remainingBytes = new byte[stream.Length - stream.Position];
            stream.Read(remainingBytes, 0, remainingBytes.Length);
            return remainingBytes;
        }

        private static readonly object lockObject = new object();

        private static readonly int maxBufferSize = int.MaxValue;

        private static readonly int maxDecompressedDataSize = int.MinValue;

        private static readonly MemoryStream syncObject = new MemoryStream(0);

        private static readonly MemoryStream compressedData = new MemoryStream(0);

        private static readonly byte previousContainer;

    }
}