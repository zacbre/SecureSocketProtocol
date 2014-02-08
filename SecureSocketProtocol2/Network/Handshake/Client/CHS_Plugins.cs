using SecureSocketProtocol2.Network.Messages;
using SecureSocketProtocol2.Network.Messages.TCP;
using SecureSocketProtocol2.Plugin;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Network.Handshake.Client
{
    internal class CHS_Plugins : Handshake
    {
        private int PluginCount = 0;
        public CHS_Plugins(SSPClient client)
            : base(client)
        {

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
            IPlugin[] Plugins = Client.onGetPlugins();
            this.PluginCount = Plugins.Length;

            SyncObject syncObject = null;
            if (!(syncObject = base.ReceiveMessage((IMessage message) =>
            {
                MsgPluginCount MsgCount = message as MsgPluginCount;
                if (MsgCount == null)
                    return false;
                PluginCount = MsgCount.PluginCount;
                return true;
            })).Wait<bool>(false))
            {
                Client.Disconnect();
                if (syncObject.TimedOut)
                    throw new Exception("A timeout occured, this means the server did not respond for ~30 seconds");
                throw new Exception("Failed to retrieve the plugin information");
            }

            if (Plugins.Length != PluginCount)
            {
                Client.Disconnect();
                throw new Exception("The client is missing a few plugin(s), add the plugin(s) in order to connect");
            }
            for (int i = 0; i < PluginCount; i++)
            {
                if (!(syncObject = base.ReceiveMessage((IMessage message) =>
                {
                    MsgGetPluginInfo MsgInfo = message as MsgGetPluginInfo;
                    if (MsgInfo == null)
                        return false;

                    bool FoundPlugin = false;
                    for (int j = 0; j < Plugins.Length; j++)
                    {
                        ulong Id = Client.Connection.pluginSystem.GetPluginId(Plugins[j]);
                        if (MsgInfo.PluginId == Id)
                        {
                            base.SendMessage(new MsgGetPluginInfoResponse(Plugins[j].Name, Plugins[j].PluginVersion.ToString()));
                            FoundPlugin = true;
                            break;
                        }
                    }

                    if (!FoundPlugin)
                        return false;
                    return true;
                })).Wait<bool>(false))
                {
                    Client.Disconnect();
                    if (syncObject.TimedOut)
                        throw new Exception("A timeout occured, this means the server did not respond for ~30 seconds");
                    throw new Exception("Failed to retrieve the plugin information");
                }

                if (!(syncObject = base.ReceiveMessage((IMessage message) =>
                {
                    MsgInitPlugin msgInit = message as MsgInitPlugin;
                    if (msgInit == null)
                        return false;

                    for (int j = 0; j < Plugins.Length; j++)
                    {
                        ulong Id = Client.Connection.pluginSystem.GetPluginId(Plugins[j]);
                        if (msgInit.PluginId == Id)
                        {
                            try
                            {
                                Client.Connection.pluginSystem.AddPlugin(Plugins[j]);
                                Plugins[j].onRegisterMessages(Client.Connection.messageHandler);

                                try
                                {
                                    if (Plugins[j].AllowPluginHooks() && Plugins[j].Hooks.Count > 0)
                                    {
                                        foreach (IPluginHook hook in Plugins[j].Hooks)
                                            hook.onClientConnected();
                                    }
                                    Plugins[j].onClientConnected();
                                }
                                catch (Exception ex)
                                {
                                    Client.onException(ex, ErrorType.UserLand);
                                }
                            }
                            catch { return false; }
                            break;
                        }
                    }
                    return true;
                })).Wait<bool>(false))
                {
                    Client.Disconnect();
                    Client.onException(new Exception("Handshake went wrong, CHS_Plugins"), ErrorType.Core);
                    if (syncObject.TimedOut)
                        throw new Exception("A timeout occured, this means the server did not respond for ~30 seconds");
                    throw new Exception("Failed to retrieve the plugin information");
                }
            }


            return true;
        }
    }
}