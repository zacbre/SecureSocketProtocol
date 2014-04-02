using SecureSocketProtocol2.Network.Messages;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network
{
    public class DeepPacketInspection
    {
        private List<DPIRule> Rules;

        /// <summary>
        /// Just making it harder for a attacker to send a extra packet while playing man-in-the-middle
        /// </summary>
        private ushort PacketId = 0;

        public DeepPacketInspection()
        {
            this.Rules = new List<DPIRule>();
        }

        /// <summary>
        /// Add a rule for any packet to inspect against attacks
        /// </summary>
        /// <param name="rule">Your rule to add</param>
        public void AddRule(DPIRule rule)
        {
            if (rule == null)
                throw new ArgumentNullException("rule");

            lock (Rules)
            {
                Rules.Add(rule);
            }
        }

        /// <summary>
        /// Inspect the packet to check if there is anything wrong with it to prevent attacks
        /// </summary>
        /// <param name="data">The data to inspect</param>
        /// <param name="Header">The Packet Header</param>
        /// <returns>Can we trust this data?</returns>
        internal bool Inspect(PacketHeader Header, IMessage message = null)
        {
            lock (Rules)
            {
                try
                {
                    if (Header != null)
                    {
                        //checking the packet size
                        if (Header.PacketSize < 0 || Header.PacketSize >= Connection.MAX_PAYLOAD)
                            return false;

                        //checking if a attacker tried to send a packet
                        if (Header.CurPacketId != PacketId)
                            return false;
                        PacketId++;
                    }
                    else
                    {
                        if (message == null)
                            return false;

                        for (int i = 0; i < Rules.Count; i++)
                        {
                            if (!Rules[i].Inspect(message))
                                return false;
                        }
                    }
                }
                catch
                {
                    //if anything goes wrong this packet it must be suspicious
                    return false;
                }
                return true;
            }
        }
    }
}