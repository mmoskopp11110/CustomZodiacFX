#!/usr/bin/env python3
import iperf3
client = iperf3.Client()
client.duration = 10
client.server_hostname = '10.0.3.9'
client.port = 5201
print('Connecting to {0}:{1}'.format(client.server_hostname, client.port))
result = client.run()
if result.error:
    print(result.error)
else:
    print('')
    print('Test completed:')
    print('Average transmitted data in all sorts of networky formats:')
    print('  bits per second      (bps)   {0}'.format(result.received_bps))
    print('  Kilobits per second  (kbps)  {0}'.format(result.received_kbps))
    print('  Megabits per second  (Mbps)  {0}'.format(result.received_Mbps))
    print('  KiloBytes per second (kB/s)  {0}'.format(result.received_kB_s))
    print('  MegaBytes per second (MB/s)  {0}'.format(result.received_MB_s))
