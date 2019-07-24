from flask import Flask, \
    send_from_directory, \
    session, request, \
    redirect
from flask_socketio import SocketIO
import iperf3
import os


""""
build the app
"""
app = Flask(__name__, static_url_path='')
app.config['SECRET_KEY'] = 'not_so_secret_key'
socketio = SocketIO(app, async_mode="eventlet")


""""
threads
"""


def setup_switch():
    global switch_ready
    switch_ready = False
    print("setting up the switch")
    result = None
    while not result or result.error:
        client = iperf3.Client()
        client.duration = 1
        client.server_hostname = '10.0.3.9'
        client.port = 5201
        result = client.run()
    socketio.sleep(15)
    print("switch is ready")
    switch_ready = True
    socketio.emit("switch_ready", {})


def test_sdn_throughput():
    global switch_ready
    while not switch_ready:
        socketio.sleep(1)
    client = iperf3.Client()
    client.duration = 10
    client.server_hostname = '10.0.3.9'
    client.port = 5201
    result = client.run()
    if result.error:
        socketio.emit('sdn_throughput_result', {'throughput': -1})
        print(result.error)
    else:
        socketio.emit('sdn_throughput_result', {'throughput': result.received_Mbps})
        print('')
        print('Test completed:')
        print('Average transmitted data in all sorts of networky formats:')
        print('  bits per second      (bps)   {0}'.format(result.received_bps))
        print('  Kilobits per second  (kbps)  {0}'.format(result.received_kbps))
        print('  Megabits per second  (Mbps)  {0}'.format(result.received_Mbps))
        print('  KiloBytes per second (kB/s)  {0}'.format(result.received_kB_s))
        print('  MegaBytes per second (MB/s)  {0}'.format(result.received_MB_s))


""""
routes
"""
@app.route('/')
def home():
    return send_from_directory("./static", "index.html")


""""
socketIO handlers
"""
@socketio.on('sdn_continue')
def handle_my_custom_event(json):
    global switch_ready
    print('received json: ' + str(json))
    if json['state'] >= 2:
        return
    if json['state'] > 0:
        switch_ready = False
        socketio.start_background_task(setup_switch)
    socketio.start_background_task(test_sdn_throughput)


@socketio.on('connect')
def connect():
    global switch_ready
    if switch_ready:
        socketio.emit("switch_ready", {})
        print('Client ' + request.sid + ' connected')


@socketio.on('disconnect')
def disconnect():
    print('Client ' + request.sid + ' disconnected')


""""
run the server
"""
if __name__ == '__main__':
    socketio.start_background_task(setup_switch)
    socketio.run(app)