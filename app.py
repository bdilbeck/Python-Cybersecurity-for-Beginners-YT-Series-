from flask import Flask, redirect, url_for


app = Flask(__name__)


@app.route("/")


def home():
    return "<h1>Hello World! This is the Firewall Interface!</h1>"


@app.route("/<name>")
def user(name):
    return f"Hello {name}!"


@app.route("/admin")
def admin():
    #Redirects un-authenticated users from admin page
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run()
