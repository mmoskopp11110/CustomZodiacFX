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


def iperf_server():
    print("Starting iperf server")
    server = iperf3.Server()
    while True:
        result = server.run()


def test_sdn_throughput():
    client = iperf3.Client()
    client.duration = 1
    client.server_hostname = '127.0.0.1'
    client.port = 5201
    result = client.run()
    try:
        socketio.emit('sdn_throughput_result', {'throughput': result.received_MB_s})
    except:
        socketio.emit('sdn_throughput_result', {'throughput': -1})


""""
routes
"""
@app.route('/')
def home():
    return send_from_directory("./static", "index.html")


"""" API """
@app.route('/api/submit', methods=["POST"])
def submit():

    # redirect to processing page
    return redirect("/processing?mid=" + session["movie_id"], code=303)


""""
socketIO handlers
"""
@socketio.on('sdn_continue')
def handle_my_custom_event(json):
    print('received json: ' + str(json))
    if json['state'] >= 4:
        return
    socketio.start_background_task(test_sdn_throughput)


@socketio.on('connect')
def connect():
    print('Client ' + request.sid + ' connected')


@socketio.on('disconnect')
def disconnect():
    print('Client ' + request.sid + ' disconnected')


""""
run the server
"""
if __name__ == '__main__':
    pid = os.fork()
    if pid:
        # parent
        socketio.run(app)
    else:
        # child for mockup
        iperf_server()
