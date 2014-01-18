using SecureSocketProtocol2.Network;
using SecureSocketProtocol2.Network.Messages;
using SecureSocketProtocol2.Network.Protections;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Plugin
{
    public abstract class IPlugin
    {
        public Protection protection { get; internal set; }

        public IPlugin()
        {
            this.Hooks = new List<IPluginHook>();
        }

        public abstract string Name { get; }
        public abstract string Description { get; }
        public abstract string Author { get; }
        public abstract Version PluginVersion { get; }
        /// <summary> If True the plugin will use it's own encryption, compression techniques </summary>
        public abstract bool UseOwnProtection { get; }


        public abstract void onClientConnected();
        public abstract void onClientDisconnected();
        public abstract void onReceiveMessage(IMessage Message);
        public abstract void onRegisterMessages(MessageHandler messageHandler);
        public abstract void onAddProtection(Protection protection);

        /// <summary>The Plugin Hook is being used to redirect any traffic from the target plugin to the hook so that the hook can monitor the traffic, filter, redirect ... etc</summary>
        /// <returns>If it's allowed to hook this plugin</returns>
        public abstract bool AllowPluginHooks();

        public SSPClient Client { get; internal set; }
        public ulong PluginId { get; internal set; }
        internal List<IPluginHook> Hooks;


        /// <summary> The plugin header is used to hold extra information in the data that is going to be send </summary>
        public abstract uint PluginHeaderSize { get; }

        /// <summary>
        /// You're able to get all the clients at server-side, this method is only available for the server-sided plugin
        /// </summary>
        public GetClientsDelegate GetClients { get; internal set; }

        /// <summary>
        /// Send a message to the target client
        /// </summary>
        /// <param name="message">The message you want to send</param>
        /// <returns>If successful sending the message</returns>
        protected SSPError SendMessage(IMessage message, PluginHeaderCallback HeaderCallback = null)
        {
            if (AllowPluginHooks() && Hooks.Count > 0)
            {
                foreach (IPluginHook hook in Hooks)
                    hook.onSendMessage(ref message);
                return SSPError.ErrorSuccess;
            }

            Client.Connection.SendPayload(message, PacketId.PluginPacket, this, true, true, HeaderCallback);
            return SSPError.ErrorSuccess;
        }

        /// <summary>
        /// The Plugin Hook is being used to redirect any traffic from the target plugin to the hook so that the plugin can monitor the traffic, filter, redirect ... etc
        /// </summary>
        /// <param name="PluginHook">The Plugin Hook to use</param>
        public void InstallHook(IPluginHook PluginHook)
        {
            if (!AllowPluginHooks())
                throw new Exception("The plugin does not allow plugin hooks to be installed");

            lock (this.Hooks)
            {
                if (!this.Hooks.Contains(PluginHook))
                    this.Hooks.Add(PluginHook);
                PluginHook.Client = this.Client;
                PluginHook.Plugin = this;
            }
        }

        public void RemoveHook(IPluginHook PluginHook)
        {
            lock (this.Hooks)
            {
                if (this.Hooks.Contains(PluginHook))
                    this.Hooks.Add(PluginHook);
            }
        }
    }
}