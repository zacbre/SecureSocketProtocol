using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.SocksProxy
{
    public class ProxySettings
    {
        public SocksVersion Version;
        public string HostIp;
        public ushort HostPort;
        public string Username = "";
        public string Password = "";

        /// <param name="Version">The version of the socks to use</param>
        /// <param name="HostIp">The destination proxy ip</param>
        /// <param name="HostPort">The destination proxy port</param>
        public ProxySettings(SocksVersion Version, string HostIp, ushort HostPort)
        {
            this.Version = Version;
            this.HostIp = HostIp;
            this.HostPort = HostPort;
        }
        
        /// <param name="Version">The version of the socks to use</param>
        /// <param name="HostIp">The destination proxy ip</param>
        /// <param name="HostPort">The destination proxy port</param>
        /// <param name="Username">The username to authenicate the proxy</param>
        /// <param name="Password">The password to authenicate the proxy</param>
        public ProxySettings(SocksVersion Version, string HostIp, ushort HostPort, string Username, string Password)
        {
            this.Version = Version;
            this.HostIp = HostIp;
            this.HostPort = HostPort;
            this.Username = Username;
            this.Password = Password;
        }
    }
}