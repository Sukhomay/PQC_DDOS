from mininet.net import Mininet
from mininet.topo import Topo
from mininet.cli import CLI
from mininet.node import OVSSwitch

class AttackTopo(Topo):
    def build(self, n_bots=5):
        switch = self.addSwitch('s1')

        server = self.addHost('server')
        self.addLink(server, switch)

        for i in range(n_bots):
            bot = self.addHost(f'bot{i}')
            self.addLink(bot, switch)

def run_attack(n_bots=5):
    topo = AttackTopo(n_bots=n_bots)

    net = Mininet(
        topo=topo,
        controller=None,
        switch=OVSSwitch
    )

    net.start()

    # CRITICAL: set switch to standalone (learning mode)
    for s in net.switches:
        s.cmd('ovs-vsctl set-fail-mode', s.name, 'standalone')

    server = net.get('server')
    print("Starting server...")
    server.cmd('/home/sukhomay/Desktop/MTP/code/server &')

    for i in range(n_bots):
        bot = net.get(f'bot{i}')
        print(f"Starting bot {i}")
        bot.cmd('/home/sukhomay/Desktop/MTP/code/bot 5 1 10.0.0.1 &')

    CLI(net)
    net.stop()

if __name__ == '__main__':
    run_attack(n_bots=10)