import bcrypt
from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from dataBe import create_database

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Để dùng flash messages

def get_db_connection():
    conn = sqlite3.connect('user3.db', timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def add_user(username, password, email, access_level):
    # Mã hóa mật khẩu trước khi lưu vào cơ sở dữ liệu
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    conn = get_db_connection()
    conn.execute('''
        INSERT INTO person (username, password, email, access_level)
        VALUES (?, ?, ?, ?)
    ''', (username, hashed_password, email, access_level))
    conn.commit()
    conn.close()

def get_current_user():
    if 'user_id' in session:
        if session['user_id'] == 'admin_1':
            return {'username': 'admin_1', 'access_level': 'admin'}
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM person WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()
        return user
    return None

# Trang home
@app.route('/')
def home():
    return render_template('home.html')

# Trang admin
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    user = get_current_user()
    if user and user['access_level'] == 'admin':
        conn = get_db_connection()
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            email = request.form['email']
            role = request.form['role']
            if username and password and email and role:
                add_user(username, password, email, role)
                flash('User added successfully', 'success')
            else:
                flash('Invalid input', 'danger')
        users = conn.execute('SELECT * FROM person').fetchall()
        conn.close()
        return render_template('admin.html', users=users)
    else:
        if user:
            message = f"{user['username']} không được phép truy cập trang này, chỉ được phép truy cập bởi Admin"
        else:
            message = "Bạn không được phép truy cập trang này, chỉ được phép truy cập bởi Admin"
        return render_template('error.html', message=message)

# Trang đăng kí
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    create_database()
    if request.method == 'POST':
        username = request.form['username1']
        password = request.form['password1']
        email = request.form['email']
        access_level = 'user'
        if username and email and password and access_level:
            add_user(username, password, email, access_level)
            return redirect(url_for('login'))
        else:
            flash('Invalid', 'danger')
    return render_template('signup.html')

# Trang đăng nhập
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username2']
        password = request.form['password2']

        # Kiểm tra nếu username và password là admin_1 và 12345
        if username == 'admin_1' and password == '12345':
            flash('Login successful!', 'success')
            session['user_id'] = 'admin_1'  # Sử dụng username cho admin
            return redirect(url_for('admin'))

        # Kiểm tra thông tin đăng nhập bằng database cho các tài khoản khác
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM person WHERE username = ? ', (username,)).fetchone()
        conn.close()

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            flash('Login successful!', 'success')
            session['user_id'] = user['id']
            if user['access_level'] == 'admin':
                return redirect(url_for('admin'))
            if user['access_level'] == 'user':
                return redirect(url_for('dashboard_user'))
            if user['access_level'] == 'content manager':
                return redirect(url_for('dashboard_content_manager'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html')

# Trang thêm người dùng
@app.route('/add_user', methods=['GET', 'POST'])
def add_user_route():
    user = get_current_user()
    if user and user['access_level'] == 'admin':
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            email = request.form['email']
            access_level = request.form['role']
            if username and email and password and access_level:
                add_user(username, password, email, access_level)
                flash('User added successfully', 'success')
                return redirect(url_for('admin'))
            else:
                flash('Invalid input', 'danger')
        return render_template('admin.html')
    else:
        if user:
            message = f"{user['username']} không được phép truy cập trang này, chỉ được phép truy cập bởi Admin"
        else:
            message = "Bạn không được phép truy cập trang này, chỉ được phép truy cập bởi Admin"
        return render_template('error.html', message=message)

# Trang dashboard cho người dùng
@app.route('/dashboard_user')
def dashboard_user():
    user = get_current_user()
    if user and user['access_level'] == 'user':
        return render_template('dashboard_user.html', username=user['username'])
    else:
        flash('Access denied. You do not have permission to access this page.', 'danger')
        return redirect(url_for('login'))

# Trang dashboard cho content manager
@app.route('/dashboard_content_manager')
def dashboard_content_manager():
    user = get_current_user()
    if user and user['access_level'] == 'content manager':
        return render_template('dashboard_content_manage.html', username=user['username'])
    else:
        flash('Access denied. You do not have permission to access this page.', 'danger')
        return redirect(url_for('login'))

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

# Chỉnh sửa vai trò người dùng trực tiếp từ trang admin
@app.route('/edit_role/<int:id>', methods=['POST'])
def edit_role(id):
    user = get_current_user()
    if user and user['access_level'] == 'admin':
        new_role = request.form['role']
        conn = get_db_connection()
        conn.execute('UPDATE person SET access_level = ? WHERE id = ?', (new_role, id))
        conn.commit()
        conn.close()
        return redirect(url_for('admin'))
    else:
        if user:
            message = f"{user['username']} không được phép truy cập trang này, chỉ được phép truy cập bởi Admin"
        else:
            message = "Bạn không được phép truy cập trang này, chỉ được phép truy cập bởi Admin"
        return render_template('error.html', message=message)

# Xóa người dùng
@app.route('/delete_user/<int:id>', methods=['POST'])
def delete_user(id):
    user = get_current_user()
    if user and user['access_level'] == 'admin':
        conn = get_db_connection()
        conn.execute('DELETE FROM person WHERE id = ?', (id,))
        conn.commit()
        conn.close()
        return redirect(url_for('admin'))
    else:
        if user:
            message = f"{user['username']} không được phép truy cập trang này, chỉ được phép truy cập bởi Admin"
        else:
            message = "Bạn không được phép truy cập trang này, chỉ được phép truy cập bởi Admin"
        return render_template('error.html', message=message)

if __name__ == '__main__':
    app.run(debug=True)
