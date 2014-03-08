using SecureSocketProtocol2.Plugin;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace SecureSocketProtocol2
{
    public abstract class ServerProperties
    {
        /// <summary> The port to listen at </summary>
        public abstract ushort ListenPort { get; }

        /// <summary> The local ip used to listen at, default: 0.0.0.0 </summary>
        public abstract string ListenIp { get; }

        /// <summary> The arguments used to initialize the BaseChannel </summary>
        public abstract object[] BaseClientArguments { get; }

        /// <summary> Enable/Disable if you also want to use the UDP protocol, when enabled every client must be connected with UDP and TCP </summary>
        public abstract bool AllowUdp { get; }

        /// <summary> This certificate will help the users know they're connected over a secure connection and not being attacked by man-in-the-middle </summary>
        public abstract CertificateInfo ServerCertificate { get; }

        /// <summary> When enabled the user needs to authenicate itself with a username and password </summary>
        public abstract bool UserPassAuthenication { get; }

        /// <summary> If keyfiles are being used it will make it harder to decrypt the traffic </summary>
        public abstract Stream[] KeyFiles { get; }

        /// <summary> Generate private keys even before client(s) are connected, speeds up the connection process </summary>
        public abstract bool GenerateKeysInBackground { get; }
    }
}