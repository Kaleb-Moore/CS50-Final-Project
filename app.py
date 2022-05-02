from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request

from vaildation import AddForm

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config['SECRET_KEY'] = 'd58a2d99ba2e54d3c30128b514556136'

# Configure CS50 Library to use SQLite database
inv = SQL("sqlite:///inventory.db")

@app.route("/")
def index():
    
    parts = inv.execute("SELECT * FROM inventory")
    add = AddForm()
    return render_template("index.html", parts=parts, add=add)


@app.route("/add", methods=["GET", "POST"])
def add():
    
    if request.method == "POST":

        add = AddForm()            

        part = request.form.get("part").lower().strip()
        qty = request.form.get("quantity")
        price = request.form.get("price")  

        rows = inv.execute("SELECT * FROM inventory WHERE part = ?", part.lower())

        if len(rows) != 1 and add.validate_on_submit():
            inv.execute("INSERT INTO inventory (part, quantity, sell) VALUES (?, ?, ?)",
                        part, qty, price)
            flash(f'{add.part.data} was Successfully added!', 'success')
        else:
            flash(f"{add.part.data} is already a part. Please click that part to edit it.", 'danger')
        
        return redirect('/')

@app.route("/update", methods=["GET", "POST"])
def update():
    
    if request.method == "POST":
        part = request.form.get("update-part")
        qty = request.form.get("update-quantity")
        price = request.form.get("update-price")

        inv.execute("UPDATE inventory SET quantity = ? WHERE part = ?", qty, part)
        inv.execute("UPDATE inventory SET sell = ? WHERE part = ?", price, part)

        flash(f"{part} was successfully updated!", 'success')
        return redirect('/')

@app.route("/delete", methods=["GET", "POST"])
def delete():

    if request.method == "POST":
        part = request.form.get("update-part")

        inv.execute("DELETE FROM inventory WHERE part = ?", part)

        return redirect('/')