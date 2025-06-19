from flask import Flask, render_template
from flask_socketio import SocketIO, emit

app = Flask(__name__)
socketio = SocketIO(app)

# Dictionary to store username: public key
user_public_keys = {}

@app.route('/')
def index():
    return render_template('chat.html')

@socketio.on('public_key')
def handle_public_key(data):
    username = data['username']
    public_key = data['public_key']

    # Save the public key
    user_public_keys[username] = public_key

    # ✅ Send list of existing users to the new user
    existing_users = [
        {'username': u, 'public_key': pk}
        for u, pk in user_public_keys.items()
        if u != username
    ]
    emit('existing_users', existing_users)

    # ✅ Inform others about the new user (use correct event name)
    emit('new_user', {
        'username': username,
        'public_key': public_key
    }, broadcast=True, include_self=False)

@socketio.on('chat_message')
def handle_chat_message(data):
    emit('chat_message', data, broadcast=True)

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=10000)