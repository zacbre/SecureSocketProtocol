using System;
using System.Collections.Generic;
using System.Text;
using SecureSocketProtocol2.SocksProxy;
using System.Security.Cryptography;
using System.IO;
using SecureSocketProtocol2.Network;
using SecureSocketProtocol2.Hashers;

namespace SecureSocketProtocol2
{
    public class ClientProperties
    {
        public string HostIp { get; private set; }
        public ushort Port { get; private set; }
        public Type BaseChannel { get; private set; }
        public object[] BaseChannelArgs { get; private set; }
        public ProxySettings proxySettings { get; private set; }
        public int ConnectingTimeout;
        public byte[] PrivateKey;
        //auth
        public string Username { get; private set; }
        public string Password { get; private set; }

        public Stream[] KeyFiles { get; private set; }


        public bool AllowChannels { get; set; }
        public bool AllowPeers { get; set; }

        public ClientProperties(string HostIp, ushort Port, Type BaseChannel, object[] BaseChannelArgs, byte[] PrivateKey, Stream[] KeyFiles = null,
                                ProxySettings proxySettings = null, int ConnectingTimeout = 30000, string Username = "", string Password = "",
                                bool AllowChannels = true, bool AllowPeers = true)
        {
            this.HostIp = HostIp;
            this.Port = Port;
            this.BaseChannel = BaseChannel;
            this.BaseChannelArgs = BaseChannelArgs;
            this.proxySettings = proxySettings;
            this.ConnectingTimeout = ConnectingTimeout;
            this.PrivateKey = PrivateKey;
            this.Username = Username;
            this.KeyFiles = KeyFiles;
            this.AllowChannels = AllowChannels;
            this.AllowPeers = AllowPeers;

            if (Password != null && Password.Length > 0)
            {
                byte[] basePass = ASCIIEncoding.ASCII.GetBytes(Convert.ToBase64String(ASCIIEncoding.Unicode.GetBytes(Password)));
                PayloadWriter keyPW = new PayloadWriter();
                keyPW.WriteUInteger(new MurmurHash2Unsafe().Hash(BitConverter.GetBytes(new SuperFastHashUInt16Hack().Hash(basePass))));
                keyPW.WriteUInteger(new MurmurHash2Unsafe().Hash(BitConverter.GetBytes(new MurmurHash2Simple().Hash(basePass))));
                keyPW.WriteUInteger(new SuperFastHashInlineBitConverter().Hash(BitConverter.GetBytes(new SuperFastHashUInt16Hack().Hash(basePass))));
                keyPW.WriteBytes(SHA512Managed.Create().ComputeHash(keyPW.ToByteArray()));
                byte[] key = keyPW.ToByteArray();

                unsafe
                {
                    fixed (byte* x = basePass)
                    {
                        for (int i = 0; i < basePass.Length; i++)
                        {
                            x[i] += (byte)((x[i] ^ key[i % key.Length]) % 0xFF);
                            x[i] ^= (byte)((x[(i + 1) % basePass.Length] / 2) * key[i % key.Length]);
                            x[i] ^= (byte)Password[i % Password.Length];
                        }
                    }
                }

                //generate random bytes at the end based on the hash
                PayloadWriter Out = new PayloadWriter();
                Out.WriteBytes(basePass);

                byte[] GenKey = new byte[32];
                for (int i = 0; i < GenKey.Length; i++)
                {
                    GenKey[i] = (byte)((basePass[i % basePass.Length] + key[i % key.Length]) % 0xFF);

                    if ((GenKey[((i * 2) / 3) % GenKey.Length] ^ (byte)(key[i % key.Length] ^ GenKey[i])) > 0)
                        GenKey[((i * 2) / 3) % GenKey.Length] ^= (byte)(key[i % key.Length] ^ GenKey[i]);
                    else
                        GenKey[(i * 3) % GenKey.Length] ^= (byte)((basePass[i % basePass.Length] << 8) % 0xFF);
                }
                Out.WriteBytes(GenKey);

                this.Password = BitConverter.ToString(Out.ToByteArray()).Replace("-", "");
            }
            Password = ""; //remove from memory hopefully
        }
    }
}