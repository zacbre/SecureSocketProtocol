using SecureSocketProtocol2.Encryptions;
using SecureSocketProtocol2.Hashers;
using SecureSocketProtocol2.Misc;
using SecureSocketProtocol2.Network.Messages;
using SecureSocketProtocol2.Network.Messages.TCP;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Handshake.Client
{
    internal class CHS_KeyExchange : Handshake
    {
        public CHS_KeyExchange(SSPClient client)
            : base(client)
        {

        }

        public override HandshakeType[] ServerTypes
        {
            get
            {
                return new HandshakeType[]
                {
                    HandshakeType.SendMessage,
                    HandshakeType.SendMessage,
                    HandshakeType.ReceiveMessage,
                };
            }
        }

        public override HandshakeType[] ClientTypes
        {
            get
            {
                return new HandshakeType[]
                {
                    HandshakeType.ReceiveMessage,
                    HandshakeType.ReceiveMessage,
                    HandshakeType.SendMessage,
                };
            }
        }

        public override bool onHandshake()
        {
            //wait for RSA from server
            RSAEncryption RSA = null;
            SyncObject syncObject = null;
            DiffieHellman diffieHellman = new DiffieHellman(256);

            if (!base.ReceiveMessage((IMessage message) =>
            {
                MsgRsaPublicKey rsaKey = message as MsgRsaPublicKey;

                if (rsaKey != null)
                {
                    RSA = new RSAEncryption(Connection.RSA_KEY_SIZE, "", rsaKey.PublicKey, true); // <- private key not public, don't get confused of the argument ITS PRIVATE KEY
                    return true;
                }
                return false;
            }).Wait<bool>(false, 30000))
            {
                if (syncObject.TimedOut)
                    throw new TimeoutException(TimeOutMessage);
                Client.Disconnect();
                throw new Exception("The RSA Exchange failed");
            }

            bool BlockedCertificate = false;
            if (!(syncObject = base.ReceiveMessage((IMessage message) =>
            {
                MsgServerEncryption mse = message as MsgServerEncryption;

                if (mse != null)
                {
                    Client.UseUDP = mse.UseUdp;

                    //read the Diffie-Hellman key
                    long index = Client.PrivateKeyOffset % 65535;
                    if (index <= 4)
                        index = 10;

                    byte[] diffieLen = new byte[4];
                    Array.Copy(mse.Key, index - 4, diffieLen, 0, diffieLen.Length);
                    byte[] diffieData = new byte[BitConverter.ToInt32(diffieLen, 0)];
                    Array.Copy(mse.Key, index, diffieData, 0, diffieData.Length); //copy the diffie-hellman key in between random data

                    //fix RSA Encrypted Data
                    Array.Copy(mse.Key, mse.Key.Length - (diffieLen.Length + diffieData.Length), mse.Key, index - 4, diffieLen.Length + diffieData.Length);
                    Array.Resize(ref mse.Key, mse.Key.Length - (diffieLen.Length + diffieData.Length)); //set original size back

                    //check if key is original
                    uint KeyHash = BitConverter.ToUInt32(new CRC32().ComputeHash(mse.Key), 0);

                    diffieHellman.GenerateResponse(new PayloadReader(diffieData));
                    Client.Certificate = mse.certificate;

                    if (!Client.onVerifyCertificate(mse.certificate))
                    {
                        BlockedCertificate = true;
                        return false;
                    }

                    base.SendMessage(new MsgDiffiehellman(diffieHellman.GetDiffie()));
                    Client.Connection.protection.ApplyPrivateKey(diffieHellman.Key); //apply salt key
                    mse.Key = RSA.Decrypt(mse.Key, 0, mse.Key.Length);//decrypt key
                    Client.Connection.protection.ApplyPrivateKey(mse.Key); //apply secure key
                    return true;
                }
                return false;
            })).Wait<bool>(false, 30000))
            {
                Client.Disconnect();
                if (!BlockedCertificate)
                {
                    if (syncObject.TimedOut)
                        throw new TimeoutException(TimeOutMessage);
                    throw new Exception("Diffie-Hellman key-exchange failed.");
                }
                throw new Exception("The certificate provided by the server was blocked by the user");
            }


            return true;
        }
    }
}
