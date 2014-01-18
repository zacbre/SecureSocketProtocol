using System;
using System.Collections.Generic;
using System.Text;
using SecureSocketProtocol2.SocksProxy;
using System.Security.Cryptography;
using System.IO;

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

        public ClientProperties(string HostIp, ushort Port, Type BaseChannel, object[] BaseChannelArgs, byte[] PrivateKey, Stream[] KeyFiles,
                                ProxySettings proxySettings = null, int ConnectingTimeout = 30000, string Username = "", string Password = "")
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

            SHA512Managed sha = new SHA512Managed();
            MD5 md = MD5.Create();
            byte[] hashed = null;

            if (Password == null)
                Password = "";

            for (int i = 0; i < 5; i++)
            {
                if (hashed == null)
                    hashed = sha.ComputeHash(ASCIIEncoding.Unicode.GetBytes(Password));
                hashed = md.ComputeHash(hashed);
                hashed = sha.ComputeHash(hashed);
            }
            this.Password = BitConverter.ToString(hashed).Replace("-", "");
            Password = ""; //remove from memory hopefully
        }
    }
}