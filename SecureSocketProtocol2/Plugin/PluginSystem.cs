using SecureSocketProtocol2.Hashers;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol2.Plugin
{
    public class PluginSystem
    {
        private SortedList<ulong, IPlugin> plugins;
        public SSPClient Client { get; private set; }

        public IPlugin[] Plugins
        {
            get
            {
                lock (plugins)
                {
                    IPlugin[] plugs = new IPlugin[plugins.Count];
                    plugins.Values.CopyTo(plugs, 0);
                    return plugs;
                }
            }
        }

        public PluginSystem(SSPClient client)
        {
            this.plugins = new SortedList<ulong, IPlugin>();
            this.Client = client;
        }

        internal IPlugin AddPlugin(IPlugin plugin, GetClientsDelegate getClientsDelegate)
        {
            lock (plugins)
            {
                ulong PluginId = GetPluginId(plugin);
                if (plugins.ContainsKey(PluginId))
                    throw new Exception("The plugin " + plugin.Name + " is already registered");
                plugin.Client = Client;
                plugin.PluginId = PluginId;
                plugin.GetClients = getClientsDelegate;
                plugins.Add(PluginId, plugin);
                return plugin;
            }
        }
        internal void AddPlugin(IPlugin plugin)
        {
            lock (plugins)
            {
                ulong PluginId = GetPluginId(plugin);
                if (plugins.ContainsKey(PluginId))
                    throw new Exception("The plugin " + plugin.Name + " is already registered");
                plugin.Client = Client;
                plugin.PluginId = PluginId;
                plugins.Add(PluginId, plugin);
            }
        }

        public ulong GetPluginId(IPlugin plugin)
        {
            MurmurHash2UInt32Hack hasher = new MurmurHash2UInt32Hack();
            uint val1 = hasher.Hash(ASCIIEncoding.Unicode.GetBytes(plugin.Name));
            uint val2 = hasher.Hash(ASCIIEncoding.Unicode.GetBytes(plugin.PluginVersion.ToString()));
            return (ulong)(val1 + val2);
        }

        public IPlugin GetPlugin(ulong PluginId)
        {
            IPlugin plugin = null;
            if (plugins.TryGetValue(PluginId, out plugin))
                return plugin;
            return null;
        }
    }
}