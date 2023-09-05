from flask import Flask, redirect, url_for, render_template, jsonify
from flask_socketio import SocketIO
import secrets



app = Flask(__name__)

secret_key = secrets.token_hex(16)
app.config['SECRET_KEY'] = secret_key
socketio = SocketIO(app)

@app.route('/', methods=['GET'])
def get_blocked_ips_():
    with open('blacklist.txt','r') as file:
        file_content = file.read()
        return render_template('interface.html', content=file_content)

@app.route("/admin")
def admin():
    #Redirects un-authenticated users from admin page
    return redirect(url_for("home"))

@socketio.on('connect')
def on_connect():
    print("Client connected")

if __name__ == "__main__":
    app.run()

 #app.run(debug=True, port=5000)
