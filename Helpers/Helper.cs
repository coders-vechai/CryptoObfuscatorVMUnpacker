using System;
using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
namespace CryptoObfuscatorUnpacker
{
    public class StringCounts
    {
        Dictionary<string, int> strings = new Dictionary<string, int>(StringComparer.Ordinal);

        public IEnumerable<string> Strings => strings.Keys;
        public int NumStrings => strings.Count;

        public void Add(string s)
        {
            strings.TryGetValue(s, out int count);
            strings[s] = count + 1;
        }

        public bool Exists(string s)
        {
            if (s == null)
                return false;
            return strings.ContainsKey(s);
        }

        public bool All(IList<string> list)
        {
            foreach (var s in list)
            {
                if (!Exists(s))
                    return false;
            }
            return true;
        }

        public bool Exactly(IList<string> list) => list.Count == strings.Count && All(list);

        public int Count(string s)
        {
            strings.TryGetValue(s, out int count);
            return count;
        }
    }

    public class FieldTypes : StringCounts
    {
        public FieldTypes(TypeDef type) => Initialize(type.Fields);
        public FieldTypes(IEnumerable<FieldDef> fields) => Initialize(fields);

        void Initialize(IEnumerable<FieldDef> fields)
        {
            if (fields == null)
                return;
            foreach (var field in fields)
            {
                var type = field.FieldSig.GetFieldType();
                if (type != null)
                    Add(type.FullName);
            }
        }
    }

    public class LocalTypes : StringCounts
    {
        public LocalTypes(MethodDef method)
        {
            if (method != null && method.Body != null)
                Initialize(method.Body.Variables);
        }

        public LocalTypes(IEnumerable<Local> locals) => Initialize(locals);

        void Initialize(IEnumerable<Local> locals)
        {
            if (locals == null)
                return;
            foreach (var local in locals)
                Add(local.Type.FullName);
        }
    }
}
