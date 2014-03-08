using SecureSocketProtocol2.Interfaces;
using SecureSocketProtocol2.Misc;
using SecureSocketProtocol2.Network;
using SecureSocketProtocol2.Network.Messages;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Plugin
{
    public abstract class IPluginHook
    {
        public IClient Client { get; internal set; }
        public IPlugin Plugin { get; internal set; }

        public IPluginHook()
        {

        }

        /// <summary>
        /// This method gets triggered if the client is connected
        /// </summary>
        public abstract void onClientConnected();

        /// <summary>
        /// This method gets triggered if the client is disconnected
        /// </summary>
        public abstract void onClientDisconnected();

        /// <summary>
        /// This method gets triggered if any data was received
        /// </summary>
        /// <param name="data">The Data</param>
        /// <returns>If false the method onReceiveData will not be triggered in the plugin</returns>
        public abstract bool onReceiveData(ref byte[] data);

        /// <summary>
        /// This method gets triggered if any message was received
        /// </summary>
        /// <param name="data">The Message</param>
        /// <returns>If false the method onReceiveMessage will not be triggered in the plugin</returns>
        public abstract bool onReceiveMessage(ref IMessage message);

        /// <summary>
        /// This method gets triggered if any data was going to be send
        /// </summary>
        /// <param name="data">The Data</param>
        /// <param name="Offset">The index of where the data starts</param>
        /// <param name="Length">The length of data</param>
        public abstract void onSendData(ref NetworkPayloadWriter npw);

        /// <summary>
        /// This method gets triggered if any message was going to be send
        /// </summary>
        /// <param name="message">The Message</param>
        public abstract void onSendMessage(ref IMessage message);
    }
}