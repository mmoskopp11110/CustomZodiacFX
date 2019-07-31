from flask import Flask, \
    send_from_directory, \
    session, request, \
    redirect
from flask_socketio import SocketIO
import iperf3


""""
build the app
"""
app = Flask(__name__, static_url_path='')
app.config['SECRET_KEY'] = 'not_so_secret_key'
socketio = SocketIO(app, async_mode="eventlet")


""""
threads
"""


def test_sdn_throughput():
    """
    Test tcp throughput and send result via socketio
    :return:
    """
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
def sdn_continue(json):
    """
    Handle "sdn_continue" socketio event
    :param json: dictionary that should contain "state" between 0 and 2 which indicates the state
    of the frontend. (0: init state, 1: after first measurement, 2: finished)
    :return:
    """
    print('received json: ' + str(json))
    if json['state'] >= 2:
        return
    socketio.start_background_task(test_sdn_throughput)


@socketio.on('connect')
def connect():
    """
    Placeholder for handling socketio connections.
    Replies with "switch_ready" socketio event
    :return:
    """
    socketio.emit("switch_ready", {})
    print('Client ' + request.sid + ' connected')


@socketio.on('disconnect')
def disconnect():
    """
    Placeholder for handling socketio connections.
    :return:
    """
    print('Client ' + request.sid + ' disconnected')


""""
run the server
"""
if __name__ == '__main__':
    socketio.run(app)