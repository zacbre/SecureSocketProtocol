using SecureSocketProtocol2.Plugin;
using System;
using System.Collections.Generic;
using System.Text;

namespace TestPlugin
{
    public class TestPlug : IPlugin
    {

        public override string Name
        {
            get { return "TestPlugin"; }
        }

        public override string Description
        {
            get { return "Just a test plugin."; }
        }

        public override string Author
        {
            get { return "DragonHunter"; }
        }

        public override Version PluginVersion
        {
            get { return new Version(1, 0); }
        }

        public override bool UseOwnProtection
        {
            get { return false; }
        }

        public override void onClientConnected()
        {

        }

        public override void onClientDisconnected()
        {

        }

        public override void onReceiveMessage(SecureSocketProtocol2.Network.Messages.IMessage Message)
        {

        }

        public override void onRegisterMessages(SecureSocketProtocol2.Network.Messages.MessageHandler messageHandler)
        {

        }

        public override void onAddProtection(SecureSocketProtocol2.Network.Protections.Protection protection)
        {

        }

        public override bool AllowPluginHooks()
        {
            return false;
        }

        public override uint PluginHeaderSize
        {
            get { return 5; }
        }
    }
}