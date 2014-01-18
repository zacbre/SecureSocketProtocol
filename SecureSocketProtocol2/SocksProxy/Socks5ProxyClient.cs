using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace SecureSocketProtocol2.SocksProxy
{
    public class Socks5ProxyClient
    {
        private const int SOCKS5_DEFAULT_PORT = 1080;
        public const byte SOCKS5_VERSION_NUMBER = 5;
        public const byte SOCKS5_RESERVED = 0x00;
        public const byte SOCKS5_AUTH_NUMBER_OF_AUTH_METHODS_SUPPORTED = 2;
        public const byte SOCKS5_AUTH_METHOD_NO_AUTHENTICATION_REQUIRED = 0x00;
        public const byte SOCKS5_AUTH_METHOD_GSSAPI = 0x01;
        public const byte SOCKS5_AUTH_METHOD_USERNAME_PASSWORD = 0x02;
        public const byte SOCKS5_AUTH_METHOD_IANA_ASSIGNED_RANGE_BEGIN = 0x03;
        public const byte SOCKS5_AUTH_METHOD_IANA_ASSIGNED_RANGE_END = 0x7f;
        public const byte SOCKS5_AUTH_METHOD_RESERVED_RANGE_BEGIN = 0x80;
        public const byte SOCKS5_AUTH_METHOD_RESERVED_RANGE_END = 0xfe;
        public const byte SOCKS5_AUTH_METHOD_REPLY_NO_ACCEPTABLE_METHODS = 0xff;
        public const byte SOCKS5_CMD_REPLY_SUCCEEDED = 0x00;
        public const byte SOCKS5_CMD_REPLY_GENERAL_SOCKS_SERVER_FAILURE = 0x01;
        public const byte SOCKS5_CMD_REPLY_CONNECTION_NOT_ALLOWED_BY_RULESET = 0x02;
        public const byte SOCKS5_CMD_REPLY_NETWORK_UNREACHABLE = 0x03;
        public const byte SOCKS5_CMD_REPLY_HOST_UNREACHABLE = 0x04;
        public const byte SOCKS5_CMD_REPLY_CONNECTION_REFUSED = 0x05;
        public const byte SOCKS5_CMD_REPLY_TTL_EXPIRED = 0x06;
        public const byte SOCKS5_CMD_REPLY_COMMAND_NOT_SUPPORTED = 0x07;
        public const byte SOCKS5_CMD_REPLY_ADDRESS_TYPE_NOT_SUPPORTED = 0x08;
        public const byte SOCKS5_ADDRTYPE_IPV4 = 0x01;
        public const byte SOCKS5_ADDRTYPE_DOMAIN_NAME = 0x03;
        public const byte SOCKS5_ADDRTYPE_IPV6 = 0x04;

        public enum ProxyCommand
        {
            SOCKS5_CMD_CONNECT = 0x01,
            SOCKS5_CMD_BIND = 0x02,
            SOCKS5_CMD_UDP_ASSOCIATE = 0x03
        }

        public string ProxyHost { get; set; }
        public ushort ProxyPort { get; set; }
        public string ProxyUserName { get; set; }
        public string ProxyPassword { get; set; }
        public Socket TcpClient { get; set; }
        public SocksAuthentication ProxyAuthMethod { get; set; }

        /// <summary>
        /// Authentication itemType.
        /// </summary>
        public enum SocksAuthentication
        {
            /// <summary>
            /// No authentication used.
            /// </summary>
            None,
            /// <summary>
            /// Username and password authentication.
            /// </summary>
            UsernamePassword
        }

        public Socks5ProxyClient() { }
        public Socks5ProxyClient(string proxyHost)
        {
            if (String.IsNullOrEmpty(proxyHost))
                throw new ArgumentNullException("proxyHost");

            this.ProxyHost = proxyHost;
            this.ProxyPort = SOCKS5_DEFAULT_PORT;
        }

        public Socks5ProxyClient(string proxyHost, ushort proxyPort)
        {
            if (String.IsNullOrEmpty(proxyHost))
                throw new ArgumentNullException("proxyHost");

            if (proxyPort <= 0 || proxyPort > 65535)
                throw new ArgumentOutOfRangeException("proxyPort", "port must be greater than zero and less than 65535");

            this.ProxyHost = proxyHost;
            this.ProxyPort = proxyPort;
        }

        public Socks5ProxyClient(string proxyHost, string proxyUserName, string proxyPassword)
        {
            if (String.IsNullOrEmpty(proxyHost))
                throw new ArgumentNullException("proxyHost");

            if (proxyUserName == null)
                throw new ArgumentNullException("proxyUserName");

            if (proxyPassword == null)
                throw new ArgumentNullException("proxyPassword");

            this.ProxyHost = proxyHost;
            this.ProxyPort = SOCKS5_DEFAULT_PORT;
            this.ProxyUserName = proxyUserName;
            this.ProxyPassword = proxyPassword;
        }

        /// <summary>
        /// Create a Socks5 proxy client object.  
        /// </summary>
        /// <param name="proxyHost">Host name or IP address of the proxy server.</param>
        /// <param name="proxyPort">Port used to connect to proxy server.</param>
        /// <param name="proxyUserName">Proxy authentication user name.</param>
        /// <param name="proxyPassword">Proxy authentication password.</param>
        public Socks5ProxyClient(string proxyHost, ushort proxyPort, string proxyUserName, string proxyPassword)
        {
            if (String.IsNullOrEmpty(proxyHost))
                throw new ArgumentNullException("proxyHost");

            if (proxyPort <= 0 || proxyPort > 65535)
                throw new ArgumentOutOfRangeException("proxyPort", "port must be greater than zero and less than 65535");

            if (proxyUserName == null)
                throw new ArgumentNullException("proxyUserName");

            if (proxyPassword == null)
                throw new ArgumentNullException("proxyPassword");

            this.ProxyHost = proxyHost;
            this.ProxyPort = proxyPort;
            this.ProxyUserName = proxyUserName;
            this.ProxyPassword = proxyPassword;
        }

        public Socket CreateConnection(int ConnectionTimeout = 10000)
        {
            try
            {
                // if we have no connection, create one
                if (TcpClient == null)
                {
                    if (String.IsNullOrEmpty(ProxyHost))
                        throw new Exception("ProxyHost property must contain a value.");

                    if (ProxyPort <= 0 || ProxyPort > 65535)
                        throw new Exception("ProxyPort value must be greater than zero and less than 65535");

                    //  create new tcp client object to the proxy server
                    TcpClient = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    // attempt to open the connection
                    TcpClient.Connect(ProxyHost, ProxyPort);

                    /*IAsyncResult ar = TcpClient.BeginConnect(ProxyHost, ProxyPort, null, null);
                    if(!ar.AsyncWaitHandle.WaitOne(ConnectionTimeout, false))
                    {
                        TcpClient.Close();
                        throw new Exception();
                    }
                    TcpClient.EndConnect(ar);*/
                }

                //  determine which authentication method the client would like to use
                DetermineClientAuthMethod();

                // negotiate which authentication methods are supported / accepted by the server
                NegotiateServerAuthMethod();

                // return the open proxied tcp client object to the caller for normal use
                return TcpClient;
            } catch
            {
                throw new Exception("Connection to proxy host " + ProxyHost + " on port " + ProxyPort + " failed.");
            }
        }

        private void DetermineClientAuthMethod()
        {
            //  set the authentication itemType used based on values inputed by the user
            if (ProxyUserName != null && ProxyPassword != null)
            {
                if (ProxyUserName.Length == 0)
                    ProxyAuthMethod = SocksAuthentication.None;
                else
                    ProxyAuthMethod = SocksAuthentication.UsernamePassword;
            }
            else
            {
                ProxyAuthMethod = SocksAuthentication.None;
            }
        }

        private void NegotiateServerAuthMethod()
        {
            byte[] authRequest = new byte[4];
            authRequest[0] = SOCKS5_VERSION_NUMBER;
            authRequest[1] = SOCKS5_AUTH_NUMBER_OF_AUTH_METHODS_SUPPORTED;
            authRequest[2] = SOCKS5_AUTH_METHOD_NO_AUTHENTICATION_REQUIRED;
            authRequest[3] = SOCKS5_AUTH_METHOD_USERNAME_PASSWORD;

            TcpClient.Send(authRequest);
            byte[] response = new byte[2];
            TcpClient.Receive(response);
            byte acceptedAuthMethod = response[1];
            if (acceptedAuthMethod == SOCKS5_AUTH_METHOD_REPLY_NO_ACCEPTABLE_METHODS)
            {
                TcpClient.Close();
                throw new Exception("The proxy destination does not accept the supported proxy client authentication methods.");
            }

            if (acceptedAuthMethod == SOCKS5_AUTH_METHOD_USERNAME_PASSWORD && ProxyAuthMethod == SocksAuthentication.None)
            {
                TcpClient.Close();
                throw new Exception("The proxy destination requires a username and password for authentication.");
            }

            if (acceptedAuthMethod == SOCKS5_AUTH_METHOD_USERNAME_PASSWORD)
            {

                // USERNAME / PASSWORD SERVER REQUEST
                // Once the SOCKS V5 server has started, and the client has selected the
                // Username/Password Authentication protocol, the Username/Password
                // subnegotiation begins.  This begins with the client producing a
                // Username/Password request:
                //
                //       +----+------+----------+------+----------+
                //       |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
                //       +----+------+----------+------+----------+
                //       | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
                //       +----+------+----------+------+----------+

                byte[] credentials = new byte[ProxyUserName.Length + ProxyPassword.Length + 3];
                credentials[0] = SOCKS5_VERSION_NUMBER;
                credentials[1] = (byte)ProxyUserName.Length;
                Array.Copy(ASCIIEncoding.ASCII.GetBytes(ProxyUserName), 0, credentials, 2, ProxyUserName.Length);
                credentials[ProxyUserName.Length + 2] = (byte)ProxyPassword.Length;
                Array.Copy(ASCIIEncoding.ASCII.GetBytes(ProxyPassword), 0, credentials, ProxyUserName.Length + 3, ProxyPassword.Length);
                TcpClient.Send(credentials);

                // USERNAME / PASSWORD SERVER RESPONSE
                // The server verifies the supplied UNAME and PASSWD, and sends the
                // following response:
                //
                //   +----+--------+
                //   |VER | STATUS |
                //   +----+--------+
                //   | 1  |   1    |
                //   +----+--------+
                //
                // A STATUS field of X'00' indicates success. If the server returns a
                // `failure' (STATUS value other than X'00') status, it MUST close the
                // connection.
                TcpClient.Receive(response);
                if (response[1] != 0)
                {
                    throw new Exception("The username or password was incorrect");
                }
            }
        }

        private byte GetDestAddressType(string host)
        {
            IPAddress ipAddr = null;

            bool result = IPAddress.TryParse(host, out ipAddr);

            if (!result)
                return SOCKS5_ADDRTYPE_DOMAIN_NAME;

            switch (ipAddr.AddressFamily)
            {
                case System.Net.Sockets.AddressFamily.InterNetwork:
                    return SOCKS5_ADDRTYPE_IPV4;
                case System.Net.Sockets.AddressFamily.InterNetworkV6:
                    return SOCKS5_ADDRTYPE_IPV6;
                default:
                    throw new Exception("The host addess " + host + " of type '{1}' is not a supported address type.  The supported types are InterNetwork and InterNetworkV6.");
            }
        }

        private byte[] GetDestAddressBytes(byte addressType, string host)
        {
            switch (addressType)
            {
                case SOCKS5_ADDRTYPE_IPV4:
                case SOCKS5_ADDRTYPE_IPV6:
                    return IPAddress.Parse(host).GetAddressBytes();
                case SOCKS5_ADDRTYPE_DOMAIN_NAME:
                    //  create a byte array to hold the host name bytes plus one byte to store the length
                    byte[] bytes = new byte[host.Length + 1];
                    //  if the address field contains a fully-qualified domain name.  The first
                    //  octet of the address field contains the number of octets of name that
                    //  follow, there is no terminating NUL octet.
                    bytes[0] = Convert.ToByte(host.Length);
                    Encoding.ASCII.GetBytes(host).CopyTo(bytes, 1);
                    return bytes;
                default:
                    return null;
            }
        }

        private byte[] GetDestPortBytes(int value)
        {
            byte[] array = new byte[2];
            array[0] = Convert.ToByte(value / 256);
            array[1] = Convert.ToByte(value % 256);
            return array;
        }

        public void SendCommand(ProxyCommand command, string destinationHost, int destinationPort)
        {
            byte addressType = GetDestAddressType(destinationHost);
            byte[] destAddr = GetDestAddressBytes(addressType, destinationHost);
            byte[] destPort = GetDestPortBytes(destinationPort);

            //  The connection request is made up of 6 bytes plus the
            //  length of the variable address byte array
            //
            //  +----+-----+-------+------+----------+----------+
            //  |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
            //  +----+-----+-------+------+----------+----------+
            //  | 1  |  1  | X'00' |  1   | Variable |    2     |
            //  +----+-----+-------+------+----------+----------+
            //
            // * VER protocol version: X'05'
            // * CMD
            //   * CONNECT X'01'
            //   * BIND X'02'
            //   * UDP ASSOCIATE X'03'
            // * RSV RESERVED
            // * ATYP address itemType of following address
            //   * IP V4 address: X'01'
            //   * DOMAINNAME: X'03'
            //   * IP V6 address: X'04'
            // * DST.ADDR desired destination address
            // * DST.PORT desired destination port in network octet order            

            byte[] request = new byte[4 + destAddr.Length + 2];
            request[0] = SOCKS5_VERSION_NUMBER;
            request[1] = (byte)command;
            request[2] = SOCKS5_RESERVED;
            request[3] = addressType;
            destAddr.CopyTo(request, 4);
            destPort.CopyTo(request, 4 + destAddr.Length);

            // send connect request.
            TcpClient.Send(request);

            //  PROXY SERVER RESPONSE
            //  +----+-----+-------+------+----------+----------+
            //  |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
            //  +----+-----+-------+------+----------+----------+
            //  | 1  |  1  | X'00' |  1   | Variable |    2     |
            //  +----+-----+-------+------+----------+----------+
            //
            // * VER protocol version: X'05'
            // * REP Reply field:
            //   * X'00' succeeded
            //   * X'01' general SOCKS server failure
            //   * X'02' connection not allowed by ruleset
            //   * X'03' Network unreachable
            //   * X'04' Host unreachable
            //   * X'05' Connection refused
            //   * X'06' TTL expired
            //   * X'07' Command not supported
            //   * X'08' Address itemType not supported
            //   * X'09' to X'FF' unassigned
            //* RSV RESERVED
            //* ATYP address itemType of following address

            byte[] response = new byte[200];
            int recv = TcpClient.Receive(response);
            byte replyCode = response[1];

            //  evaluate the reply code for an error condition
            if (replyCode != SOCKS5_CMD_REPLY_SUCCEEDED)
                HandleProxyCommandError(response, destinationHost, destinationPort);
        }

        private void HandleProxyCommandError(byte[] response, string destinationHost, int destinationPort)
        {
            string proxyErrorText;
            byte replyCode = response[1];
            byte addrType = response[3];
            string addr = "";
            Int16 port = 0;

            switch (addrType)
            {
                case SOCKS5_ADDRTYPE_DOMAIN_NAME:
                    int addrLen = Convert.ToInt32(response[4]);
                    byte[] addrBytes = new byte[addrLen];
                    for (int i = 0; i < addrLen; i++)
                        addrBytes[i] = response[i + 5];
                    addr = System.Text.ASCIIEncoding.ASCII.GetString(addrBytes);
                    byte[] portBytesDomain = new byte[2];
                    portBytesDomain[0] = response[6 + addrLen];
                    portBytesDomain[1] = response[5 + addrLen];
                    port = BitConverter.ToInt16(portBytesDomain, 0);
                    break;

                case SOCKS5_ADDRTYPE_IPV4:
                    byte[] ipv4Bytes = new byte[4];
                    for (int i = 0; i < 4; i++)
                        ipv4Bytes[i] = response[i + 4];
                    IPAddress ipv4 = new IPAddress(ipv4Bytes);
                    addr = ipv4.ToString();
                    byte[] portBytesIpv4 = new byte[2];
                    portBytesIpv4[0] = response[9];
                    portBytesIpv4[1] = response[8];
                    port = BitConverter.ToInt16(portBytesIpv4, 0);
                    break;

                case SOCKS5_ADDRTYPE_IPV6:
                    byte[] ipv6Bytes = new byte[16];
                    for (int i = 0; i < 16; i++)
                        ipv6Bytes[i] = response[i + 4];
                    IPAddress ipv6 = new IPAddress(ipv6Bytes);
                    addr = ipv6.ToString();
                    byte[] portBytesIpv6 = new byte[2];
                    portBytesIpv6[0] = response[21];
                    portBytesIpv6[1] = response[20];
                    port = BitConverter.ToInt16(portBytesIpv6, 0);
                    break;
            }

            switch (replyCode)
            {
                case SOCKS5_CMD_REPLY_GENERAL_SOCKS_SERVER_FAILURE:
                    proxyErrorText = "a general socks destination failure occurred";
                    break;
                case SOCKS5_CMD_REPLY_CONNECTION_NOT_ALLOWED_BY_RULESET:
                    proxyErrorText = "the connection is not allowed by proxy destination rule set";
                    break;
                case SOCKS5_CMD_REPLY_NETWORK_UNREACHABLE:
                    proxyErrorText = "the network was unreachable";
                    break;
                case SOCKS5_CMD_REPLY_HOST_UNREACHABLE:
                    proxyErrorText = "the host was unreachable";
                    break;
                case SOCKS5_CMD_REPLY_CONNECTION_REFUSED:
                    proxyErrorText = "the connection was refused by the remote network";
                    break;
                case SOCKS5_CMD_REPLY_TTL_EXPIRED:
                    proxyErrorText = "the time to live (TTL) has expired";
                    break;
                case SOCKS5_CMD_REPLY_COMMAND_NOT_SUPPORTED:
                    proxyErrorText = "the command issued by the proxy client is not supported by the proxy destination";
                    break;
                case SOCKS5_CMD_REPLY_ADDRESS_TYPE_NOT_SUPPORTED:
                    proxyErrorText = "the address type specified is not supported";
                    break;
                default:
                    proxyErrorText = String.Format(CultureInfo.InvariantCulture, "that an unknown reply with the code value '{0}' was received by the destination", replyCode.ToString(CultureInfo.InvariantCulture));
                    break;
            }
            throw new Exception(String.Format(CultureInfo.InvariantCulture, "The {0} concerning destination host {1} port number {2}.  The destination reported the host as {3} port {4}.", proxyErrorText, destinationHost, destinationPort, addr, port.ToString(CultureInfo.InvariantCulture)));
        }
    }
}