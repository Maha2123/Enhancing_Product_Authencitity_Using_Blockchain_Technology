from flask import Flask, render_template, request, redirect, url_for, session, flash
from index import BlockChain
import json
import smtplib as smtp
from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import time

app = Flask(__name__)
app.secret_key = "alkdjfalkdjf"

import smtplib
def create_connection():
    conn = sqlite3.connect('database.db')
    return conn

def create_table():
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL,
                        password TEXT NOT NULL)''')
    conn.commit()
    conn.close()

create_table()
def send_email():
    # Email configuration
    smtp_server = 'smtp.gmail.com'
    smtp_port = 465  # For SSL
    sender_email = 'karthikaivy@gmail.com'
    # sender_email = mm
    receiver_email = str(mm)
    password = 'brtkzlgnewulyvqd'  # Your email password

    # Create a secure SSL connection to the SMTP server
    connection = smtplib.SMTP_SSL(smtp_server, smtp_port)

    try:
        # Login to the email server
        connection.login(sender_email, password)

        # Construct the email message
        subject = 'Fake Product Alert'
        body = 'Dear recipient,\n\nThis is to inform you about a fake product.\n\nBest regards,\nSender'
        message = f'Subject: {subject}\n\n{body}'

        # Send the email
        connection.sendmail(sender_email, receiver_email, message)
        flash("Email sent successfully!")
    except Exception as e:
        flash(f"Error sending email: {e}")
    finally:
        # Close the connection
        connection.close()


@app.route('/')
def index():
    return render_template('p1.html')

@app.route('/adminlogin')
def adminlogin1():
    return render_template('adminlogin.html')

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/index')
def user():
    return render_template('index.html')
@app.route("/adminlogin", methods=["POST", "GET"])
def adminlogin():
	if request.method == "POST":
		user = request.form["username"]
		pswd = request.form["password"]

		if user == "Admin":
			if pswd == "password":
				session["user"] = "Admin"
				#return redirect(url_for("admin"))
				return redirect(url_for("home"))
	else:
		return render_template('login.html')
                  




@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        global mm
        username = request.form['username']
        password = request.form['password']
        mm = request.form['email'] # user mail ID
        hashed_password = generate_password_hash(password)

        conn = create_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user:
            flash('Username already exists!', 'error')
            conn.close()
            return redirect(url_for('register'))

        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        conn.close()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    global mm
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        mm = request.form["mail"]

        conn = create_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        conn.close()

        if user and check_password_hash(user[2], password):
            session['logged_in'] = True
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('check'))
        else:
            flash('Invalid username or password!', 'error')
            
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route("/verify/<kid>", methods=["GET"])
def verify(kid):
		return render_template('verify.html', keyId=kid)


@app.route("/verify", methods=["POST"])

def success():
    post_data = request.form["keyId"]

    with open('./NODES/N1/blockchain.json', 'r') as bfile:
        n1_data = str(bfile.read())
    with open('./NODES/N2/blockchain.json', 'r') as bfile:
        n2_data = str(bfile.read())
    with open('./NODES/N3/blockchain.json', 'r') as bfile:
        n3_data = str(bfile.read())
    with open('./NODES/N4/blockchain.json', 'r') as bfile:
        n4_data = str(bfile.read())

    pd = str(post_data)

    if (pd in n1_data) and (pd in n2_data) and (pd in n3_data) and (pd in n4_data):

        with open('./NODES/N1/blockchain.json', 'r') as bfile:
            for x in bfile:
                if pd in x:
                    a = json.loads(x)["data"]
                    b = a.replace("'", "\"")
                    data = json.loads(b)

                    product_brand = data["Manufacturer"]
                    product_name = data["ProductName"]
                    product_batch = data["ProductBatch"]
                    manuf_date = data["ProductManufacturedDate"]
                    expiry_date = data["ProductExpiryDate"]
                    product_id = data["ProductId"]
                    product_price = data["ProductPrice"]
                    product_size = data["ProductSize"]
                    product_type = data["ProductType"]
        
        return render_template('success.html', brand=product_brand, name=product_name, batch=product_batch, manfdate=manuf_date, exprydate=expiry_date, id=product_id, price=product_price, size=product_size, type=product_type)
    
    else:
        try:
            send_email()
            flash("Email sent successfully!", 'success') 
            print('Success')

        except:
            # Email configuration
            smtp_server = 'smtp.gmail.com'
            smtp_port = 465  # For SSL
            sender_email = 'karthikaivy@gmail.com'
            receiver_email = str(mm)
            password = 'brtkzlgnewulyvqd'  # Your email password
        
            # Create a secure SSL connection to the SMTP server
            connection = smtplib.SMTP_SSL(smtp_server, smtp_port)
            connection.login(sender_email, password)
            subject = 'Fake Product Alert'
            body = 'Dear recipient,\n\nThis is to inform you about a fake product.\n\nBest regards,\nSender'
            message = f'Subject: {subject}\n\n{body}'    
            connection.sendmail(sender_email, receiver_email, message)
            flash("Email sent successfully!")
            connection.close()

        # You can add your email sending logic here
        return render_template('fraud.html', message="Fake Product")

            # try:
            #     # Login to the email server
            #     connection.login(sender_email, password)
        
            #     # Construct the email message
            #     subject = 'Fake Product Alert'
            #     body = 'Dear recipient,\n\nThis is to inform you about a fake product.\n\nBest regards,\nSender'
            #     message = f'Subject: {subject}\n\n{body}'
        
            #     # Send the email
            #     connection.sendmail(sender_email, receiver_email, message)
            #     flash("Email sent successfully!")
            # except Exception as e:
            #     flash(f"Error sending email: {e}")
            # finally:
            #     # Close the connection
            #     connection.close()
            
        
                # Construct the email message
 
        
                # Send the email

            # except Exception as e:
            #     flash(f"Error sending email: {e}")
            # finally:
            #     # Close the connection
            # print('Success')


@app.route("/addproduct", methods=["POST", "GET"])
def addproduct():
	if request.method == "POST":
		brand	 = request.form["brand"]
		name	 = request.form["name"]
		batch	 = request.form["batch"]
		pid	 	 = request.form["id"]
		manfdate = request.form["manfdate"]
		exprydate= request.form["exprydate"]
		price	 = request.form["price"]
		size	 = request.form["size"]
		ptype	 = request.form["type"]
		
		print(brand, name, batch, manfdate, exprydate, pid, price, size, ptype)
		bc = BlockChain()
		bc.addProduct(brand, name, batch, manfdate, exprydate, pid, price, size, ptype)
		
		flash("Product added successfully to the Blockchain")
		# return render_template('home.html')
		return redirect(url_for('home'))
	else:
		# return render_template('home.html')
		return redirect(url_for('home'))


@app.route("/admin")
def admin():
	if session["user"] == "Admin":
		return redirect(url_for('admin'))
	else:
		return redirect(url_for('login'))


@app.route("/verifyNodes")
def verifyNodes():
	bc = BlockChain()
	isBV = bc.isBlockchainValid()

	if isBV:
		flash("All Nodes of Blockchain are valid")
		return redirect(url_for('admin'))
	else:
		flash("Blockchain Nodes are not valid")
		return redirect(url_for('admin'))


@app.route("/medicine")
def medicine():
	return render_template('MedicinePage.html')


@app.route("/fertilizer")
def fertilizer():
	return render_template('FertilizersPage.html')


@app.route("/shoes")
def shoes():
	return render_template('ShoesPage.html')

#check
@app.route("/check")
def check():
	return render_template('check.html')

@app.route("/dress")
def dress():
	return render_template('dressPage.html')


@app.route("/logout")
def logout():
	session["user"] = ""
	return redirect(url_for('login'))


if __name__ == "__main__":
    app.run(debug=True)
    session["user"] = ""