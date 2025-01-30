from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/")
def home():
    return "<h1>Hello from Flask behind OpenBSD httpd!</h1>"

@app.route("/signup", methods=["GET","POST"])
def signup():
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        # Do your logic... store in DB or in memory, etc.
        return f"<h1>Thanks, {email}!</h1>"
    return '''
        <form method="post">
          <input name="email" placeholder="Enter your email">
          <button type="submit">Sign Up</button>
        </form>
    '''

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
