#!/usr/bin/python

# (c) Copyright 2015-2016 Hewlett Packard Enterprise Development LP
#
# GNU Zebra is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2, or (at your option) any
# later version.
#
# GNU Zebra is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GNU Zebra; see the file COPYING.  If not, write to the Free
# Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

from opsvsi.docker import *
from opsvsi.opsvsitest import *
import re


class QosCliTest(OpsVsiTest):
    def setupNet(self):
        host_opts = self.getHostOpts()
        switch_opts = self.getSwitchOpts()
        topo = SingleSwitchTopo(k=0, hopts=host_opts, sopts=switch_opts)
        self.net = Mininet(topo, switch=VsiOpenSwitch,
                           host=Host, link=OpsVsiLink,
                           controller=None, build=True)


class Test_qos_cli():
    def setup_class(cls):
        Test_qos_cli.test = QosCliTest()

    def teardown_class(cls):
        Test_qos_cli.test.net.stop()

    def setup(self):
        self.s1 = Test_qos_cli.test.net.switches[0]

    def setUp_qosApplyGlobal(self):
        self.s1.cmdCLI('end')
        self.s1.cmdCLI('configure terminal')

        self.s1.cmdCLI('apply qos queue-profile '
                       'default schedule-profile default')

        self.s1.cmdCLI('no qos queue-profile p1')
        self.s1.cmdCLI('qos queue-profile p1')
        self.s1.cmdCLI('map queue 4 local-priority 3')
        self.s1.cmdCLI('map queue 5 local-priority 2')
        self.s1.cmdCLI('map queue 6 local-priority 1')
        self.s1.cmdCLI('map queue 7 local-priority 0')
        self.s1.cmdCLI('map queue 0 local-priority 7')
        self.s1.cmdCLI('map queue 1 local-priority 6')
        self.s1.cmdCLI('map queue 2 local-priority 5')
        self.s1.cmdCLI('map queue 3 local-priority 4')
        self.s1.cmdCLI('exit')

        self.s1.cmdCLI('no qos schedule-profile p1')
        self.s1.cmdCLI('qos schedule-profile p1')
        self.s1.cmdCLI('dwrr queue 4 weight 40')
        self.s1.cmdCLI('dwrr queue 5 weight 50')
        self.s1.cmdCLI('dwrr queue 6 weight 60')
        self.s1.cmdCLI('dwrr queue 7 weight 70')
        self.s1.cmdCLI('dwrr queue 0 weight 1')
        self.s1.cmdCLI('dwrr queue 1 weight 10')
        self.s1.cmdCLI('dwrr queue 2 weight 20')
        self.s1.cmdCLI('dwrr queue 3 weight 30')
        self.s1.cmdCLI('exit')

    def setUp_qosApplyPort(self):
        self.s1.cmdCLI('end')
        self.s1.cmdCLI('configure terminal')

        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('no lag 10')
        self.s1.cmdCLI('no apply qos schedule-profile')
        self.s1.cmdCLI('exit')

        self.s1.cmdCLI('interface lag 10')
        self.s1.cmdCLI('no apply qos schedule-profile')
        self.s1.cmdCLI('exit')

        self.s1.cmdCLI('no qos schedule-profile p1')
        self.s1.cmdCLI('qos schedule-profile p1')
        self.s1.cmdCLI('dwrr queue 4 weight 40')
        self.s1.cmdCLI('dwrr queue 5 weight 50')
        self.s1.cmdCLI('dwrr queue 6 weight 60')
        self.s1.cmdCLI('dwrr queue 7 weight 70')
        self.s1.cmdCLI('dwrr queue 0 weight 1')
        self.s1.cmdCLI('dwrr queue 1 weight 10')
        self.s1.cmdCLI('dwrr queue 2 weight 20')
        self.s1.cmdCLI('dwrr queue 3 weight 30')
        self.s1.cmdCLI('exit')

        self.s1.cmdCLI('end')
        self.s1.cmdCLI('configure terminal')

    def setUp_qosCosMap(self):
        self.s1.cmdCLI('end')
        self.s1.cmdCLI('configure terminal')

        self.s1.cmdCLI('no qos cos-map 7')

    def setup_qosCosPort(self):
        self.s1.cmdCLI('end')
        self.s1.cmdCLI('configure terminal')

        self.s1.cmdCLI('no qos cos')

        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('no lag 10')
        self.s1.cmdCLI('no qos trust')
        self.s1.cmdCLI('no qos cos')

        self.s1.cmdCLI('interface lag 10')
        self.s1.cmdCLI('no qos trust')
        self.s1.cmdCLI('no qos cos')

        self.s1.cmdCLI('end')
        self.s1.cmdCLI('configure terminal')

    def setUp_qosDscpMap(self):
        self.s1.cmdCLI('end')
        self.s1.cmdCLI('configure terminal')

        self.s1.cmdCLI('no qos dscp-map 38')

    def setUp_qosDscpPort(self):
        self.s1.cmdCLI('end')
        self.s1.cmdCLI('configure terminal')

        self.s1.cmdCLI('no qos dscp')

        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('no lag 10')
        self.s1.cmdCLI('no qos trust')
        self.s1.cmdCLI('no qos dscp')

        self.s1.cmdCLI('interface lag 10')
        self.s1.cmdCLI('no qos trust')
        self.s1.cmdCLI('no qos dscp')

        self.s1.cmdCLI('end')
        self.s1.cmdCLI('configure terminal')

    def setUp_qosQueueProfile(self):
        self.s1.cmdCLI('end')
        self.s1.cmdCLI('configure terminal')

        self.s1.cmdCLI('apply qos queue-profile default '
                       'schedule-profile default')

        self.s1.cmdCLI('no qos queue-profile p1')
        self.s1.cmdCLI('no qos queue-profile p2')

    def setUp_qosQueueStatistics(self):
        self.s1.cmdCLI('end')
        self.s1.cmdCLI('configure terminal')

        self.s1.cmdCLI('no interface lag 10')

    def setUp_qosScheduleProfile(self):
        self.s1.cmdCLI('end')
        self.s1.cmdCLI('configure terminal')

        self.s1.cmdCLI('apply qos queue-profile default '
                       'schedule-profile default')

        self.s1.cmdCLI('no qos schedule-profile p1')
        self.s1.cmdCLI('no qos schedule-profile p2')

    def setUp_qosTrustGlobal(self):
        self.s1.cmdCLI('end')
        self.s1.cmdCLI('configure terminal')

        self.s1.cmdCLI('no qos trust')

    def setUp_qosTrustPort(self):
        self.s1.cmdCLI('end')
        self.s1.cmdCLI('configure terminal')

        self.s1.cmdCLI('no qos trust')

        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('no lag 10')
        self.s1.cmdCLI('no qos trust')

        self.s1.cmdCLI('interface lag 10')
        self.s1.cmdCLI('no qos trust')

        self.s1.cmdCLI('end')
        self.s1.cmdCLI('configure terminal')

    def teardown(self):
        pass

    def __del__(self):
        del self.test

    def get_local_priority_range(self):
        printed_show_output = self.s1.cmdCLI('do show qos cos-map default')

        min_local_priority = sys.maxint
        max_local_priority = None
        lines = printed_show_output.split('\n')
        for line in lines:
            if line[0].isdigit():
                line_split = line.split(' ')

                local_priority = -1
                ints_found_count = 0
                for split in line_split:
                    if split.isdigit():
                        ints_found_count += 1
                    if ints_found_count == 2:
                        local_priority = int(split)
                        break

                if local_priority > max_local_priority:
                    max_local_priority = local_priority

                if local_priority < min_local_priority:
                    min_local_priority = local_priority

        local_priority_range = [min_local_priority, max_local_priority]
        return local_priority_range

    def test_qosCosMapShowRunningConfigWithDefault(self):
        self.setUp_qosCosMap()
        self.s1.cmdCLI('qos cos-map 1 local-priority 0 '
                       'color green name "Background"')
        out = self.s1.cmdCLI('do show running-config')
        assert 'qos' not in out
        assert 'cos-map' not in out
        assert 'code_point' not in out
        assert 'local_priority' not in out
        assert 'color' not in out
        assert 'name' not in out

    def test_qosCosMapShowCommand(self):
        self.setUp_qosCosMap()
        self.s1.cmdCLI('qos cos-map 7 local-priority 2 '
                       'color yellow name MyName2')
        out = self.s1.cmdCLI('do show qos cos-map')
        assert '7          2              yellow  MyName2' in out

    def test_qosCosMapShowCommandWithDefault(self):
        self.setUp_qosCosMap()
        self.s1.cmdCLI('qos cos-map 7 local-priority 2 '
                       'color yellow name MyName2')
        out = self.s1.cmdCLI('do show qos cos-map default')
        assert '7          7              green   Network_Control' in out
        self.setUp_qosCosMap()

    def test_qosCosPortShowRunningConfig(self):
        # This command is not supported in dill.
        return
        self.setup_qosCosPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('qos trust none')
        self.s1.cmdCLI('qos cos 1')
        out = self.s1.cmdCLI('do show running-config')
        assert 'override' in out

    def test_qosCosPortShowRunningConfigInterface(self):
        # This command is not supported in dill.
        return
        self.setup_qosCosPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('qos trust none')
        self.s1.cmdCLI('qos cos 1')
        out = self.s1.cmdCLI('do show running-config interface 1')
        assert 'override' in out

    def test_qosCosPortShowInterface(self):
        # This command is not supported in dill.
        return
        self.setup_qosCosPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('qos trust none')
        self.s1.cmdCLI('qos cos 1')
        out = self.s1.cmdCLI('do show interface 1')
        assert 'override' in out
        self.setup_qosCosPort()

    def test_qosDscpMapShowRunningConfigWithDefault(self):
        self.setUp_qosDscpMap()
        self.s1.cmdCLI('qos dscp-map 38 local-priority 4 '
                       'cos 4 color red name AF43')
        out = self.s1.cmdCLI('do show running-config')
        assert 'qos' not in out
        assert 'dscp-map' not in out
        assert 'code_point' not in out
        assert 'local_priority' not in out
        assert 'cos' not in out
        assert 'color' not in out
        assert 'name' not in out

    def test_qosDscpMapShowCommand(self):
        self.setUp_qosDscpMap()
        self.s1.cmdCLI('qos dscp-map 38 local-priority 2 '
                       'color yellow name MyName2')
        out = self.s1.cmdCLI('do show qos dscp-map')
        assert '38         2              yellow  MyName2' in out

    def test_qosDscpMapShowCommandWithDefault(self):
        self.setUp_qosDscpMap()
        self.s1.cmdCLI('qos dscp-map 38 local-priority 2 '
                       'color yellow name MyName2')
        out = self.s1.cmdCLI('do show qos dscp-map default')
        assert '38         4              red     AF43' in out
        self.setUp_qosDscpMap()

    def test_qosDscpPortShowRunningConfig(self):
        self.setUp_qosDscpPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('qos trust none')
        self.s1.cmdCLI('qos dscp 1')
        out = self.s1.cmdCLI('do show running-config')
        assert 'qos dscp 1' in out

    def test_qosDscpPortShowRunningConfigInterface(self):
        self.setUp_qosDscpPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('qos trust none')
        self.s1.cmdCLI('qos dscp 1')
        out = self.s1.cmdCLI('do show running-config interface 1')
        assert 'qos dscp 1' in out

    def test_qosDscpPortShowInterface(self):
        self.setUp_qosDscpPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('qos trust none')
        self.s1.cmdCLI('qos dscp 1')
        out = self.s1.cmdCLI('do show interface 1')
        assert 'override' in out
        self.setUp_qosDscpPort()

    def test_qosQueueProfileShowCommand(self):
        self.setUp_qosQueueProfile()
        self.s1.cmdCLI('qos queue-profile p1')
        self.s1.cmdCLI('name queue 1 QueueName')
        out = self.s1.cmdCLI('do show qos queue-profile p1')
        assert 'QueueName' in out

    def test_qosQueueProfileShowCommandWithIllegalName(self):
        self.setUp_qosQueueProfile()
        out = self.s1.cmdCLI('do show qos queue-profile '
                             'NameThatIsLongerThan64Characterssssssssssssssss'
                             'ssssssssssssssssss')
        assert 'length up to' in out
        out = self.s1.cmdCLI('do show qos queue-profile '
                             'NameWithIllegalCh@r@cter$')
        assert 'The allowed characters are' in out

    def test_qosQueueProfileShowCommandShowsAllProfiles(self):
        self.setUp_qosQueueProfile()

        # Create a 'complete' profile.
        self.s1.cmdCLI('qos queue-profile p1')
        self.s1.cmdCLI('map queue 0 local-priority 0')
        self.s1.cmdCLI('map queue 0 local-priority 1')
        self.s1.cmdCLI('map queue 0 local-priority 2')
        self.s1.cmdCLI('map queue 0 local-priority 3')
        self.s1.cmdCLI('map queue 0 local-priority 4')
        self.s1.cmdCLI('map queue 0 local-priority 5')
        self.s1.cmdCLI('map queue 0 local-priority 6')
        self.s1.cmdCLI('map queue 0 local-priority 7')
        self.s1.cmdCLI('exit')

        # Create an 'incomplete' profile.
        self.s1.cmdCLI('qos queue-profile p2')
        self.s1.cmdCLI('map queue 0 local-priority 0')
        self.s1.cmdCLI('exit')

        out = self.s1.cmdCLI('do show qos queue-profile')
        assert 'incomplete     p2' in out
        assert 'complete       p1' in out
        assert 'complete       factory-default' in out
        assert 'applied        default' in out

    def test_qosQueueProfileShowCommandFactoryDefault(self):
        self.setUp_qosQueueProfile()
        out = self.s1.cmdCLI('do show qos queue-profile factory-default')
        assert 'queue_num' in out

    def test_qosQueueProfileShowCommandWithNonExistentProfile(self):
        self.setUp_qosQueueProfile()
        out = self.s1.cmdCLI('do show qos queue-profile NonExistent')
        assert 'does not exist' in out
        self.setUp_qosQueueProfile()

    def test_qosShowQueueStatisticsCommandWithSingleInterface(self):
        # TODO: Figure out why queue statistics do not show in the py tests.
        return
        self.setUp_qosQueueStatistics()
        out = self.s1.cmdCLI('do show interface 1 queues')
        assert 'Q0' in out
        assert 'Q1' in out
        assert 'Q2' in out
        assert 'Q3' in out
        assert 'Q4' in out
        assert 'Q5' in out
        assert 'Q6' in out
        assert 'Q7' in out

    def test_qosShowQueueStatisticsCommandWithAllInterfaces(self):
        # TODO: Figure out why queue statistics do not show in the py tests.
        return
        self.setUp_qosQueueStatistics()
        out = self.s1.cmdCLI('do show interface queues')
        assert 'Q0' in out
        assert 'Q1' in out
        assert 'Q2' in out
        assert 'Q3' in out
        assert 'Q4' in out
        assert 'Q5' in out
        assert 'Q6' in out
        assert 'Q7' in out
        self.setUp_qosQueueStatistics()

    def test_qosScheduleProfileShowCommand(self):
        self.setUp_qosScheduleProfile()
        self.s1.cmdCLI('qos schedule-profile p1')
        self.s1.cmdCLI('strict queue 1')
        out = self.s1.cmdCLI('do show qos schedule-profile p1')
        assert 'strict' in out
        assert '1' in out

    def test_qosScheduleProfileShowCommandWithIllegalName(self):
        self.setUp_qosScheduleProfile()
        out = self.s1.cmdCLI('do show qos schedule-profile '
                             'NameThatIsLongerThan64Charactersssssssssssssss'
                             'sssssssssssssssssss')
        assert 'length up to' in out
        out = self.s1.cmdCLI('do show qos schedule-profile '
                             'NameWithIllegalCh@r@cter$')
        assert 'The allowed characters are' in out

    def test_qosScheduleProfileShowCommandShowsAllProfiles(self):
        self.setUp_qosScheduleProfile()

        # Create a 'complete' profile.
        self.s1.cmdCLI('qos schedule-profile p1')
        self.s1.cmdCLI('strict queue 0')
        self.s1.cmdCLI('exit')

        # Create an 'incomplete' profile.
        self.s1.cmdCLI('qos schedule-profile p2')
        self.s1.cmdCLI('exit')

        out = self.s1.cmdCLI('do show qos schedule-profile')
        assert 'incomplete     p2' in out
        assert 'complete       p1' in out
        assert 'complete       factory-default' in out
        assert 'applied        default' in out

    def test_qosScheduleProfileShowCommandFactoryDefault(self):
        self.setUp_qosScheduleProfile()
        out = self.s1.cmdCLI('do show qos schedule-profile factory-default')
        assert 'queue_num' in out

    def test_qosScheduleProfileShowCommandWithNonExistentProfile(self):
        self.setUp_qosScheduleProfile()
        out = self.s1.cmdCLI('do show qos schedule-profile NonExistent')
        assert 'does not exist' in out
        self.setUp_qosScheduleProfile()

    def test_qosTrustGlobalShowRunningConfigWithDefault(self):
        self.setUp_qosTrustGlobal()
        self.s1.cmdCLI('qos trust none')
        out = self.s1.cmdCLI('do show running-config')
        assert 'qos' not in out
        assert 'trust' not in out

    def test_qosTrustGlobalShowCommand(self):
        self.setUp_qosTrustGlobal()
        self.s1.cmdCLI('qos trust dscp')
        out = self.s1.cmdCLI('do show qos trust')
        assert 'qos trust dscp' in out
        self.setUp_qosTrustGlobal()

    def test_qosTrustGlobalShowCommandWithDefault(self):
        self.setUp_qosTrustGlobal()
        self.s1.cmdCLI('qos trust dscp')
        out = self.s1.cmdCLI('do show qos trust default')
        assert 'qos trust none' in out
        self.setUp_qosTrustGlobal()

    def test_qosTrustPortShowRunningConfigWithDefault(self):
        self.setUp_qosTrustPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('qos trust none')
        out = self.s1.cmdCLI('do show running-config')
        assert 'qos' in out
        assert 'trust' in out

    def test_qosTrustPortShowRunningConfigWithNonDefault(self):
        self.setUp_qosTrustPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('qos trust dscp')
        out = self.s1.cmdCLI('do show running-config')
        assert 'qos trust dscp' in out

    def test_qosTrustPortShowRunningConfigInterfaceWithDefault(self):
        self.setUp_qosTrustPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('qos trust none')
        out = self.s1.cmdCLI('do show running-config interface 1')
        assert 'qos trust' in out

    def test_qosTrustPortShowRunningConfigInterfaceWithNonDefault(self):
        self.setUp_qosTrustPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('qos trust dscp')
        out = self.s1.cmdCLI('do show running-config interface 1')
        assert 'qos trust dscp' in out

    def test_qosTrustPortShowInterfaceWithDefault(self):
        self.setUp_qosTrustPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('qos trust none')
        out = self.s1.cmdCLI('do show interface 1')
        assert 'qos trust none' in out

    def test_qosTrustPortShowInterfaceWithNonDefault(self):
        self.setUp_qosTrustPort()
        self.s1.cmdCLI('interface 1')
        self.s1.cmdCLI('qos trust dscp')
        out = self.s1.cmdCLI('do show interface 1')
        assert 'qos trust dscp' in out
        self.setUp_qosTrustPort()
