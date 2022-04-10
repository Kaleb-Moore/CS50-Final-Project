import re
from telnetlib import AO
from turtle import setundobuffer
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import login_required, apology

from datetime import datetime

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///user.db")
inv = SQL("sqlite:///inventory.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    user_id = session["user_id"]

    return render_template("index.html")


@app.route("/receive", methods=["GET", "POST"])
@login_required
def receive():
    
    if request.method == "POST":
        part = request.form.get("part").lower()
        qty = request.form.get("qty")
        cost = request.form.get("cost")
        price = request.form.get("price")  

        if not part:
            return apology("Please provide a part name")
        if not qty:
            return apology("Please provide a qty")
        if not cost:
            return apology("Please provide a cost")
        if not price:
            return apology("Please provide a sell price")

        
        try:
            qty = int(request.form.get("qty"))
        except:
            return apology("Quantity must be an integer")
            
        try:
            cost = int(request.form.get("cost"))
        except:
            return apology("Cost must be an integer")

        try:
            price = int(request.form.get("price"))
        except:
            return apology("Sell Price must be an integer")

        rows = inv.execute("SELECT * FROM inventory WHERE part = ?", part.lower())

        if len(rows) != 1:
            inv.execute("INSERT INTO inventory (part, quantity, cost, sell) VALUES (?, ?, ?, ?)",
                        part, qty, cost, price)
        else:
            update = inv.execute("SELECT * FROM inventory WHERE part = ?", part)[0]["quantity"]
            inv.execute("UPDATE inventory SET quantity = (? + ?) WHERE part = ?", update, qty, part)

        inv.execute("INSERT INTO transactions (part, quantity, cost, sell, type) VALUES (?, ?, ?, ?, ?)",
                    part, qty, cost, price, "received")
        return render_template("index.html")
    else:
        return render_template("receive.html")
    

@app.route("/logs")
@login_required
def logs():
    """Show history of transactions"""
    user_id = session["user_id"]
    


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("Invalid username/password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        hash = generate_password_hash(password)

        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hash)
        return redirect('/')

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    
    if request.method == "POST":
        part = request.form.get("part").lower().strip()
        qty = request.form.get("qty") 

        if not part:
            return apology("Please provide a part name")
        if not qty:
            return apology("Please provide a qty")

        try:
            qty = int(request.form.get("qty"))
        except:
            return apology("Quantity must be an integer")

        canSell = inv.execute("SELECT * FROM inventory WHERE part = ?", part)


        if len(canSell) != 1 or canSell[0]["quantity"] == 0:
            return apology("You don't have that part to sell")
        else:
            cost = canSell[0]["cost"]
            sell = canSell[0]["sell"]
            inv.execute("UPDATE inventory SET quantity = (? - ?) WHERE part = ?", canSell[0]["quantity"], qty, part)
            inv.execute("INSERT INTO transactions (part, quantity, cost, sell, type) VALUES (?, ?, ?, ?, ?)",
                        part, qty, cost, sell, "sell")
            return render_template("index.html")

    else:
        return render_template("sell.html")
