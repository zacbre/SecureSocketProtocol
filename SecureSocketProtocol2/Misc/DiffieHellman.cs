using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Misc
{
    /// <summary>
    /// Represents the Diffie-Hellman algorithm.
    /// </summary>
    public class DiffieHellman : IDisposable
    {
        private Random random;

        /// <summary>
        /// The number of bits to generate.
        /// </summary>
        private int bits = 256;

        /// <summary>
        /// The shared prime.
        /// </summary>
        BigInteger prime;
        /// <summary>
        /// The shared base.
        /// </summary>
        BigInteger g;
        /// <summary>
        /// The private prime.
        /// </summary>
        BigInteger mine;

        /// <summary>
        /// The final key.
        /// </summary>
        byte[] key;
        /// <summary>
        /// The string representation/packet.
        /// </summary>
        string representation;

        /// <summary>
        /// Gets the final key to use for encryption.
        /// </summary>
        public byte[] Key
        {
            get { return key; }
        }

        public DiffieHellman()
        {
        }

        public DiffieHellman(int bits)
        {
            this.bits = bits;
            this.random = new Random();
        }

        ~DiffieHellman()
        {
            Dispose();
        }

        /// <summary>
        /// Generates a request packet.
        /// </summary>
        /// <returns></returns>
        public DiffieHellman GenerateRequest()
        {
            // Generate the parameters.
            prime = BigInteger.genPseudoPrime(bits, 30, random);
            mine = BigInteger.genPseudoPrime(bits, 30, random);
            g = BigInteger.genPseudoPrime(bits, 30, random);

            // Gemerate the string.
            StringBuilder rep = new StringBuilder();
            rep.Append(prime.ToString(36));
            rep.Append("|");
            rep.Append(g.ToString(36));
            rep.Append("|");

            // Generate the send BigInt.
            using (BigInteger send = g.modPow(mine, prime))
            {
                rep.Append(send.ToString(36));
            }
            representation = rep.ToString();
            return this;
        }

        /// <summary>
        /// Generate a response packet.
        /// </summary>
        /// <param name="request">The string representation of the request.</param>
        /// <returns></returns>
        public DiffieHellman GenerateResponse(string request)
        {
            string[] parts = request.Split('|');

            // Generate the would-be fields.
            using (BigInteger prime = new BigInteger(parts[0], 36))
            using (BigInteger g = new BigInteger(parts[1], 36))
            using (BigInteger mine = BigInteger.genPseudoPrime(bits, 30, random))
            {
                // Generate the key.
                using (BigInteger given = new BigInteger(parts[2], 36))
                using (BigInteger key = given.modPow(mine, prime))
                {
                    this.key = key.getBytes();
                }
                // Generate the response.
                using (BigInteger send = g.modPow(mine, prime))
                {
                    this.representation = send.ToString(36);
                }
            }

            return this;
        }

        /// <summary>
        /// Generates the key after a response is received.
        /// </summary>
        /// <param name="response">The string representation of the response.</param>
        public void HandleResponse(string response)
        {
            // Get the response and modpow it with the stored prime.
            using (BigInteger given = new BigInteger(response, 36))
            using (BigInteger key = given.modPow(mine, prime))
            {
                this.key = key.getBytes();
            }
            Dispose();
        }

        public override string ToString()
        {
            return representation;
        }

        /// <summary>
        /// Ends the calculation. The key will still be available.
        /// </summary>
        public void Dispose()
        {
            if (!Object.ReferenceEquals(prime, null))
                prime.Dispose();
            if (!Object.ReferenceEquals(mine, null))
                mine.Dispose();
            if (!Object.ReferenceEquals(g, null))
                g.Dispose();

            prime = null;
            mine = null;
            g = null;

            representation = null;
        }
    }
}