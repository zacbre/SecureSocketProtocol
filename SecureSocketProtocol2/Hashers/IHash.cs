using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Hashers
{
    public interface IHashAlgorithm
    {
        UInt32 Hash(Byte[] data);
    }
    public interface ISeededHashAlgorithm : IHashAlgorithm
    {
        UInt32 Hash(Byte[] data, UInt32 seed);
    }
}