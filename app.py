from flask import Flask, redirect, url_for, render_template
import firewallalert



app = Flask(__name__)

"""@app.route("/")
def dynamic_page():
    return firewallalert.firewall()"""
    
# ^ Is this the key to making the page dynamic?

@app.route("/")
def home():
    return render_template('interface.html', info=firewallalert.blocked_ips)



@app.route("/admin")
def admin():
    #Redirects un-authenticated users from admin page
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run()
@app.route("/admin")
def admin():
    #Redirects un-authenticated users from admin page
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run()
