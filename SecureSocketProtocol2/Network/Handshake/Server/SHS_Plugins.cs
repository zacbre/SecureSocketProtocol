using SecureSocketProtocol2.Network.Messages;
using SecureSocketProtocol2.Network.Messages.TCP;
using SecureSocketProtocol2.Network.Messages.TCP.Handshake;
using SecureSocketProtocol2.Plugin;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Handshake.Server
{
    internal class SHS_Plugins : Handshake
    {
        private int PluginCount = 0;
        private GetClientsDelegate getClientsDelegate;
        public SHS_Plugins(SSPClient client, GetClientsDelegate getClientsDelegate)
            : base(client)
        {
            this.getClientsDelegate = getClientsDelegate;
        }

        public override HandshakeType[] ServerTypes
        {
            get
            {
                List<HandshakeType> types = new List<HandshakeType>();
                types.Add(HandshakeType.SendMessage);

                for (int i = 0; i < PluginCount; i++)
                {
                    types.Add(HandshakeType.SendMessage);
                    types.Add(HandshakeType.ReceiveMessage);
                    types.Add(HandshakeType.SendMessage);
                }

                return types.ToArray();
            }
        }

        public override HandshakeType[] ClientTypes
        {
            get
            {
                List<HandshakeType> types = new List<HandshakeType>();
                types.Add(HandshakeType.ReceiveMessage);

                for (int i = 0; i < PluginCount; i++)
                {
                    types.Add(HandshakeType.ReceiveMessage);
                    types.Add(HandshakeType.SendMessage);
                    types.Add(HandshakeType.ReceiveMessage);
                }

                return types.ToArray();
            }
        }

        public override bool onHandshake()
        {
            IPlugin[] plugins = Client.onGetPlugins();
            this.PluginCount = plugins.Length;
            base.SendMessage(new MsgPluginCount(plugins.Length));
            foreach (IPlugin plugin in plugins)
            {
                //lets see if client is having correct version
                Client.Connection.pluginSystem.AddPlugin(plugin, getClientsDelegate);
                plugin.onRegisterMessages(Client.Connection.messageHandler);
                base.SendMessage(new MsgGetPluginInfo(plugin.PluginId));

                if (!base.ReceiveMessage((IMessage message) =>
                {
                    MsgGetPluginInfoResponse response = message as MsgGetPluginInfoResponse;

                    if (response != null)
                    {
                        if (plugin.Name != response.PluginName || plugin.PluginVersion.ToString() != response.VersionString)
                            return false;
                        return true;
                    }
                    return false;
                }).Wait<bool>(false, 30000))
                {
                    Client.Disconnect(DisconnectReason.TimeOut);
                    Client.onException(new Exception("Handshake went wrong, SHS_Plugins"), ErrorType.Core);
                    return false;
                }

                try
                {
                    if (plugin.AllowPluginHooks() && plugin.Hooks.Count > 0)
                    {
                        foreach (IPluginHook hook in plugin.Hooks)
                            hook.onClientConnected();
                    }
                }
                catch (Exception ex)
                {
                    Client.onException(ex, ErrorType.UserLand);
                }
                plugin.onClientConnected();
                base.SendMessage(new MsgInitPlugin(plugin.PluginId));
            }
            return true;
        }
    }
}