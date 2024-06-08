from datetime import datetime

from PIL import Image
from flask import *
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from utils import *

app = Flask(__name__)
app.config[
    'SQLALCHEMY_DATABASE_URI'] = f"mysql+pymysql://{USERNAME}:{PASSWORD}@{HOSTNAME}:{PORT}/{DATABASE}?charset=utf8mb4"
db = SQLAlchemy(app)
app.secret_key = 'your_secret_key'  # 设置一个密钥，用于加密session数据


def get_user_info():
    user = User.query.get(session['user_id'])
    is_admin = AdminUser.query.get(session['user_id']).AdminIdentify
    current_user_info = {
        'name': user.UserName,
        "pic_url": user.UserPic,
        "is_admin": is_admin
    }
    return current_user_info


class User(db.Model):
    __tablename__ = 'User'
    UserID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    UserName = db.Column(db.String(30))
    UserGender = db.Column(db.Boolean)
    UserPassword = db.Column(db.String(300))
    UserTitle = db.Column(db.String(30))
    UserJoinTime = db.Column(db.DateTime, default=datetime.utcnow)
    UserPic = db.Column(db.String(256))


class AdminUser(User):
    __tablename__ = 'AdminUser'
    AdminIdentify = db.Column(db.Boolean)
    AdminProfile = db.Column(db.String(200))


class SimpleUser(User):
    __tablename__ = 'SimpleUser'
    UserReadAccess = db.Column(db.String(3))


class Piece(db.Model):
    __tablename__ = 'Piece'
    PieceID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    PieceName = db.Column(db.String(50))
    PieceType = db.Column(db.String(10))
    PieceProfile = db.Column(db.Text)
    PiecePic = db.Column(db.String(256))
    PieceAuthor = db.Column(db.String(30))
    PieceOS = db.Column(db.Boolean)
    PieceLink = db.Column(db.String(255))


class Forum(db.Model):
    __tablename__ = 'Forum'
    ForumID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ForumPieceID = db.Column(db.Integer, db.ForeignKey('Piece.PieceID'))
    ForumName = db.Column(db.String(50))
    ForumProfile = db.Column(db.Text)


class Remark(db.Model):
    __tablename__ = 'Remark'
    RemarkID = db.Column(db.BigInteger, primary_key=True, autoincrement=True)
    ForumID = db.Column(db.Integer, db.ForeignKey('Forum.ForumID'))
    UserID = db.Column(db.Integer, db.ForeignKey('User.UserID'))
    RemarkContent = db.Column(db.Text)
    RemarkTime = db.Column(db.DateTime, default=datetime.utcnow)


class Role(db.Model):
    __tablename__ = 'Role'
    RoleID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    RoleName = db.Column(db.String(30))
    RoleProfile = db.Column(db.String(400))
    RolePic = db.Column(db.String(256))
    RoleGender = db.Column(db.Boolean)
    RoleAge = db.Column(db.Integer)


class Tool(db.Model):
    __tablename__ = 'Tool'
    ToolID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ToolName = db.Column(db.String(30))
    ToolProfile = db.Column(db.String(400))
    ToolPic = db.Column(db.String(256))


class RoleLink(db.Model):
    __tablename__ = 'RoleLink'
    PieceID = db.Column(db.Integer, db.ForeignKey('Piece.PieceID'), primary_key=True)
    RoleID = db.Column(db.Integer, db.ForeignKey('Role.RoleID'), primary_key=True)


class ToolLink(db.Model):
    __tablename__ = 'ToolLink'
    ToolID = db.Column(db.Integer, db.ForeignKey('Tool.ToolID'), primary_key=True)
    PieceID = db.Column(db.Integer, db.ForeignKey('Piece.PieceID'), primary_key=True)


class Save(db.Model):
    __tablename__ = 'Save'
    UserID = db.Column(db.Integer, db.ForeignKey('User.UserID'), primary_key=True)
    PieceID = db.Column(db.Integer, db.ForeignKey('Piece.PieceID'), primary_key=True)


@app.route('/register', methods=['GET', 'POST'])
def register():
    try:
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            gender = request.form['gender']
            if gender == 'male':
                gender_num = 1
            elif gender == 'female':
                gender_num = 0
            else:
                gender_num = None
            usertype = request.form['usertype']
            verification_code = request.form.get('verification_code')  # 使用get方法以避免KeyError
            password_hash = generate_password_hash(password)

        # 检查用户名是否已存在
        # existing_user = User.query.filter_by(UserName=username).first()
        # if existing_user:
        #     flash('Username already exists. Please choose a different one.')
        #     return redirect(url_for('register'))

            # 如果用户选择注册admin，则验证校验码
            if usertype == 'admin':
                if verification_code != ADMIN_VERIFICATION_CODE:
                    flash('注册码校验错误')
                    return redirect(url_for('register'))

            if usertype == 'admin':
                new_user = AdminUser(UserName=username, UserPassword=password_hash, UserGender=gender_num,
                                     UserJoinTime=datetime.utcnow(), AdminIdentify=True, AdminProfile='Admin Profile')
                db.session.add(new_user)
            else:
                new_user = SimpleUser(UserName=username, UserPassword=password_hash, UserGender=gender_num,
                                      UserJoinTime=datetime.utcnow(), UserReadAccess='777')
                db.session.add(new_user)
            db.session.commit()

            # 处理上传的头像
            file = request.files['file']
            if file and allowed_file(file.filename):
                filename = "temp." + secure_filename(file.filename)
                if '.' in filename:
                    user_id = new_user.UserID
                    file_extension = filename.rsplit('.', 1)[1].lower()
                    destination_filename = f"{user_id}.{file_extension}"
                    file_path = 'pic/user/' + destination_filename
                    img = Image.open(file.stream)
                    img = img.resize((100,100), Image.LANCZOS)
                    img.save('./static/' + file_path)

                    # 更新用户头像路径
                    new_user.UserPic = file_path  # 注意这里保存的应是路径而非文件名
                    db.session.commit()
                else:
                    # print("上传的文件缺少扩展名，请选择正确的图片文件")
                    flash('上传的文件缺少扩展名，请选择正确的图片文件')
            else:
                # print("上传的文件类型无效或者没有选定文件")
                flash('上传的文件类型无效或者没有选定文件')

            flash('注册成功，请登录。')
            return redirect(url_for('login'))

    except Exception as e:
        # 如果触发器抛出错误，回滚会话并显示错误消息
        print("用户名已存在，请重新输入")
        print(e)
        db.session.rollback()
        flash("用户名已存在，请重新输入")
        return redirect(url_for('register'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # 查找用户
        user = User.query.filter_by(UserName=username).first()
        # SELECT * FROM User WHERE UserName = 'username' LIMIT 1;

        # 检查用户是否存在并且密码是否正确
        if user and check_password_hash(user.UserPassword, password):
            # 用户登录成功，设置会话
            session['user_id'] = user.UserID
            session['user_name'] = user.UserName
            flash('Login successful.')
            return redirect(url_for('home'))  # 重定向到主页或其他页面
        else:
            flash('Invalid username or password.')

    return render_template('login.html')


@app.route('/')
def home():
    # 检查用户是否已经登录
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # 获取当前登录用户的信息（如果已登录），并检查用户是否存在
    current_user_info = None
    if 'user_id' in session:
        user = User.query.get_or_404(session['user_id'])
        # SELECT * FROM User WHERE id = session['user_id'] LIMIT 1;

        if user is not None:  # 添加此检查以确认用户存在
            current_user_info = {
                'name': user.UserName,
                'pic_url': user.UserPic,
            }
        else:  # 如果 user 是 None，说明根据 user_id 没有找到用户，应视为未登录状态并重定向
            return redirect(url_for('login'))

    # 查询最新添加的5个作品、角色、道具和发言
    latest_pieces = Piece.query.order_by(Piece.PieceID.desc()).limit(5).all()
    # SELECT * FROM Piece ORDER BY PieceID DESC LIMIT 5;
    latest_roles = Role.query.order_by(Role.RoleID.desc()).limit(5).all()
    latest_tools = Tool.query.order_by(Tool.ToolID.desc()).limit(5).all()
    latest_remarks = Remark.query.order_by(Remark.RemarkID.desc()).limit(5).all()

    return render_template(
        'home.html',
        latest_pieces=latest_pieces,
        latest_roles=latest_roles,
        latest_tools=latest_tools,
        latest_remarks=latest_remarks,
        current_user=current_user_info
    )


@app.route('/pieces')
def pieces():
    # 检查用户是否已经登录
    if 'user_id' not in session:
        return redirect(url_for('login'))

    page_num = int(request.args.get('page', 1))
    PER_PAGE = 35
    pieces = Piece.query.order_by(Piece.PieceID).paginate(page=page_num, per_page=PER_PAGE)
    # SELECT * FROM Piece ORDER BY PieceID ASC LIMIT PER_PAGE OFFSET (page_num - 1) * PER_PAGE;
    # 跳过前(page_num - 1) * PER_PAGE条记录，以实现分页

    # 判断当前用户是否管理员
    is_admin = False
    if 'user_id' in session:
        user = AdminUser.query.get_or_404(session['user_id'])
        # SELECT * FROM AdminUser WHERE id = session['user_id'] LIMIT 1;

        # 如果用户是 AdminUser 的实例，则设置 is_admin 为 True
        if user is not None:
            is_admin = user.AdminIdentify
        print(is_admin)

    return render_template('pieces.html', pieces=pieces.items, is_admin=is_admin, current_user=get_user_info())


@app.route('/piece/<int:piece_id>')
def piece_details(piece_id):
    # 检查用户是否已经登录
    if 'user_id' not in session:
        return redirect(url_for('login'))

    piece = Piece.query.get_or_404(piece_id)

    # 获取关联的角色和道具
    roles = db.session.query(Role).join(RoleLink, Role.RoleID == RoleLink.RoleID).filter(RoleLink.PieceID == piece_id).all()
    # SELECT Role.*
    # FROM Role
    # JOIN RoleLink ON Role.RoleID = RoleLink.RoleID
    # WHERE RoleLink.PieceID = piece_id;
    tools = db.session.query(Tool).join(ToolLink, Tool.ToolID == ToolLink.ToolID).filter(ToolLink.PieceID == piece_id).all()

    return render_template('piece_details.html', piece=piece, roles=roles, tools=tools, current_user=get_user_info())


@app.route('/new_piece', methods=['GET', 'POST'])
def new_piece():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = AdminUser.query.get(session['user_id'])
    if user is None or user.AdminIdentify is None:
        flash('You must be an admin to view this page.')
        return redirect(url_for('home'))

    if request.method == 'POST':
        piece_name = request.form['piece_name']
        piece_type = request.form['piece_type']
        piece_profile = request.form['piece_profile']
        piece_author = request.form['piece_author']
        piece_os = request.form.get('piece_os') == 'True'
        piece_link = request.form['piece_link']

        new_piece = Piece(PieceName=piece_name, PieceType=piece_type, PieceProfile=piece_profile,
                          PieceAuthor=piece_author, PieceOS=piece_os, PieceLink = piece_link)
        db.session.add(new_piece)
        db.session.commit()

        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = "temp." + secure_filename(file.filename)
            print(filename)
            if '.' in filename:
                piece_id = new_piece.PieceID
                file_extension = filename.rsplit('.', 1)[1].lower()
                destination_filename = f"{piece_id}.{file_extension}"
                file_path = 'pic/piece/' + destination_filename
                img = Image.open(file.stream)
                img = img.resize((1080, 1527), Image.LANCZOS)
                img.save('./static/' + file_path)

                # 更新路径
                new_piece.PiecePic = file_path
            else:
                db.session.rollback()
                flash('上传的文件缺少扩展名，请选择正确的图片文件')
        else:
            db.session.rollback()
            flash('上传的文件类型无效或者没有选定文件')

        new_forum = Forum(ForumPieceID=new_piece.PieceID, ForumName=new_piece.PieceName, ForumProfile=new_piece.PieceProfile)
        db.session.add(new_forum)
        db.session.commit()
        flash('新作品创建成功')
        return redirect(url_for('pieces'))

    return render_template('new_piece.html')


@app.route('/piece/edit/<int:piece_id>', methods=['GET', 'POST'])
def edit_piece(piece_id):
    if 'user_id' not in session or not AdminUser.query.get(session['user_id']).AdminIdentify:
        flash('非管理员用户')
        return redirect(url_for('login'))

    piece = Piece.query.get_or_404(piece_id)

    if request.method == 'POST':
        piece.PieceName = request.form['piece_name']
        piece.PieceType = request.form['piece_type']
        piece.PieceProfile = request.form['piece_profile']
        piece.PieceAuthor = request.form['piece_author']
        piece.PieceOS = request.form.get('piece_os') == 'True'
        piece.PieceLink = request.form['piece_link']

        db.session.execute(text('CALL UpdatePieceName(:id, :name)'), {'id': piece_id, 'name': piece.PieceName})
        db.session.execute(text('CALL UpdatePieceProfile(:id, :profile)'), {'id': piece_id, 'profile': piece.PieceProfile})

        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = "tmp." + secure_filename(file.filename)
            file_extension = filename.rsplit('.', 1)[1].lower()
            destination_filename = f"{piece.PieceID}.{file_extension}"
            file_path = 'pic/piece/' + destination_filename
            img = Image.open(file.stream)
            img = img.resize((1080, 1527), Image.LANCZOS)
            img.save('./static/' + file_path)
            piece.PiecePic = file_path

        db.session.commit()
        flash('作品信息已更新。')
        return redirect(url_for('piece_details', piece_id=piece_id))

    return render_template('edit_piece.html', piece=piece, current_user=get_user_info())


@app.route('/piece/delete/<int:piece_id>', methods=['POST'])
def delete_piece(piece_id):
    if 'user_id' not in session or not AdminUser.query.get(session['user_id']).AdminIdentify:
        flash('非管理员用户')
        return redirect(url_for('login'))

    try:
        piece = Piece.query.get_or_404(piece_id)

        # 开始事务
        with db.session.begin_nested():
            # 删除与作品相关的角色关联、道具关联、收藏、论坛和发言
            RoleLink.query.filter_by(PieceID=piece_id).delete()
            # DELETE FROM RoleLink WHERE PieceID = piece_id;
            ToolLink.query.filter_by(PieceID=piece_id).delete()
            Save.query.filter_by(PieceID=piece_id).delete()

            # 删除与作品相关的论坛及其发言
            forums = Forum.query.filter_by(ForumPieceID=piece_id).all()
            # SELECT * FROM Forum WHERE ForumPieceID = piece_id;
            for forum in forums:
                Remark.query.filter_by(ForumID=forum.ForumID).delete()
                # DELETE FROM Remark WHERE ForumID = forum.ForumID;
                db.session.delete(forum)

            # 删除作品
            db.session.delete(piece)
            db.session.commit()

        flash('作品删除成功。')
    except SQLAlchemyError as e:
        db.session.rollback()
        print(f'删除作品时发生错误: {str(e)}')
        flash(f'删除作品时发生错误: {str(e)}')

    return redirect(url_for('pieces'))


@app.route('/roles', methods=['GET'])
def roles():
    # 检查用户是否已经登录
    if 'user_id' not in session:
        return redirect(url_for('login'))

    page_num = int(request.args.get('page', 1))
    PER_PAGE = 35
    roles = Role.query.order_by(Role.RoleID).paginate(page=page_num, per_page=PER_PAGE)
    # SELECT * FROM Role ORDER BY RoleID LIMIT PER_PAGE OFFSET (page_num - 1) * PER_PAGE;

    # 判断当前用户是否管理员
    is_admin = False
    if 'user_id' in session:
        user = AdminUser.query.get(session['user_id'])
        # 如果用户是 AdminUser 的实例，则设置 is_admin 为 True
        if user is not None:
            is_admin = user.AdminIdentify

    return render_template('roles.html', roles=roles.items, is_admin=is_admin, current_user=get_user_info())


@app.route('/role/<int:role_id>')
def role_details(role_id):
    # 检查用户是否已经登录
    if 'user_id' not in session:
        return redirect(url_for('login'))

    role = Role.query.get_or_404(role_id)
    # SELECT * FROM Role WHERE RoleID = role_id;

    return render_template('role_details.html', role=role, current_user=get_user_info())


@app.route('/role/edit/<int:role_id>', methods=['GET', 'POST'])
def edit_role(role_id):
    # 确保用户已登录且是管理员
    if 'user_id' not in session or not AdminUser.query.get(session['user_id']).AdminIdentify:
        flash('非管理员用户')
        return redirect(url_for('login'))

    role = Role.query.get_or_404(role_id)

    if request.method == 'POST':
        # 从表单获取数据并更新角色对象
        role.RoleName = request.form['role_name']
        role.RoleProfile = request.form['role_profile']
        role_gender = request.form['role_gender']
        if role_gender == 'male':
            gender_num = 1
        elif role_gender == 'female':
            gender_num = 0
        else:
            gender_num = None
        role.RoleGender = gender_num
        role.RoleAge = request.form['role_age']

        # 处理上传的图片
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = "tmp." + secure_filename(file.filename)
            file_extension = filename.rsplit('.', 1)[1].lower()
            destination_filename = f"{role.RoleID}.{file_extension}"
            file_path = 'pic/role/' + destination_filename
            img = Image.open(file.stream)
            img = img.resize((540, 720), Image.LANCZOS)
            img.save('./static/' + file_path)
            role.RolePic = file_path

        db.session.commit()
        flash('角色信息已更新。')
        return redirect(url_for('role_details', role_id=role_id))

    # 如果是GET请求，则显示编辑表单
    return render_template('edit_role.html', role=role, current_user=get_user_info())

@app.route('/role/delete/<int:role_id>', methods=['POST'])
def delete_role(role_id):
    if 'user_id' not in session or not AdminUser.query.get_or_404(session['user_id']).AdminIdentify:
        flash('非管理员用户')
        return redirect(url_for('login'))

    try:
        role = Role.query.get_or_404(role_id)

        # 开始事务
        with db.session.begin_nested():
            # 删除与作品相关的角色关联、道具关联、收藏、论坛和发言
            RoleLink.query.filter_by(RoleID=role_id).delete()

            # 删除作品
            db.session.delete(role)
            db.session.commit()

        flash('角色删除成功。')
    except SQLAlchemyError as e:
        db.session.rollback()
        print(f'删除角色时发生错误: {str(e)}')
        flash(f'删除角色时发生错误: {str(e)}')

    return redirect(url_for('roles'))


@app.route('/new_role', methods=['GET', 'POST'])
def new_role():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = AdminUser.query.get(session['user_id'])
    if user is None or user.AdminIdentify is None:
        flash('非管理员用户')
        return redirect(url_for('roles'))

    if request.method == 'POST':
        role_name = request.form['role_name']
        role_profile = request.form['role_profile']
        role_gender = request.form.get('role_gender')
        if role_gender == 'male':
            gender_num = 1
        elif role_gender == 'female':
            gender_num = 0
        else:
            gender_num = None
        role_age = request.form['role_age']

        new_role = Role(RoleName=role_name, RoleProfile=role_profile, RoleGender=gender_num, RoleAge=role_age)

        db.session.add(new_role)
        db.session.commit()

        file = request.files['file']
        print(request.files)
        if file and allowed_file(file.filename):
            filename = "temp." + secure_filename(file.filename)
            if '.' in filename:
                role_id = new_role.RoleID
                print(role_id)
                file_extension = filename.rsplit('.', 1)[1].lower()
                destination_filename = f"{role_id}.{file_extension}"
                file_path = 'pic/role/' + destination_filename
                img = Image.open(file.stream)
                img = img.resize((540, 720), Image.LANCZOS)
                img.save('./static/' + file_path)

                # 更新路径
                new_role.RolePic = file_path
            else:
                flash('上传的文件缺少扩展名，请选择正确的图片文件')
        else:
            flash('上传的文件类型无效或者没有选定文件')

        db.session.commit()
        flash('新角色创建成功')
        return redirect(url_for('roles'))

    return render_template('new_role.html')


@app.route('/tools', methods=['GET'])
def tools():
    # 检查用户是否已经登录
    if 'user_id' not in session:
        return redirect(url_for('login'))

    page_num = int(request.args.get('page', 1))
    PER_PAGE = 35
    tools = Tool.query.order_by(Tool.ToolID).paginate(page=page_num, per_page=PER_PAGE)

    # 判断当前用户是否管理员
    is_admin = False
    if 'user_id' in session:
        user = AdminUser.query.get(session['user_id'])
        # 如果用户是 AdminUser 的实例，则设置 is_admin 为 True
        if user is not None:
            is_admin = user.AdminIdentify

    return render_template('tools.html', tools=tools.items, is_admin=is_admin, current_user=get_user_info())


@app.route('/tool/<int:tool_id>')
def tool_details(tool_id):
    # 检查用户是否已经登录
    if 'user_id' not in session:
        return redirect(url_for('login'))

    tool = Tool.query.get_or_404(tool_id)
    return render_template('tool_details.html', tool=tool, current_user=get_user_info())


@app.route('/tool/edit/<int:tool_id>', methods=['GET', 'POST'])
def edit_tool(tool_id):
    # 确保用户已登录且是管理员
    if 'user_id' not in session or not AdminUser.query.get(session['user_id']).AdminIdentify:
        flash('You must be an admin to edit a tool.')
        return redirect(url_for('login'))

    tool = Tool.query.get_or_404(tool_id)

    if request.method == 'POST':
        # 从表单获取数据并更新工具对象
        tool.ToolName = request.form['tool_name']
        tool.ToolProfile = request.form['tool_profile']

        # 处理上传的图片
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = "tmp." + secure_filename(file.filename)
            file_extension = filename.rsplit('.', 1)[1].lower()
            destination_filename = f"{tool.ToolID}.{file_extension}"
            file_path = 'pic/tool/' + destination_filename
            img = Image.open(file.stream)
            img.save('./static/' + file_path)
            tool.ToolPic = file_path

        db.session.commit()
        flash('道具信息已更新。')
        return redirect(url_for('tool_details', tool_id=tool_id))

    # 如果是GET请求，则显示编辑表单
    return render_template('edit_tool.html', tool=tool, current_user=get_user_info())


@app.route('/tool/delete/<int:tool_id>', methods=['POST'])
def delete_tool(tool_id):
    if 'user_id' not in session or not AdminUser.query.get_or_404(session['user_id']).AdminIdentify:
        flash('非管理员用户')
        return redirect(url_for('login'))

    try:
        tool = Tool.query.get_or_404(tool_id)

        # 开始事务
        with db.session.begin_nested():
            # 删除与作品相关的角色关联、道具关联、收藏、论坛和发言
            ToolLink.query.filter_by(ToolID=tool_id).delete()

            # 删除作品
            db.session.delete(tool)
            db.session.commit()

        flash('道具删除成功。')
    except SQLAlchemyError as e:
        db.session.rollback()
        print(f'删除道具时发生错误: {str(e)}')
        flash(f'删除道具时发生错误: {str(e)}')

    return redirect(url_for('tools'))


@app.route('/new_tool', methods=['GET', 'POST'])
def new_tool():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = AdminUser.query.get(session['user_id'])
    if user is None or user.AdminIdentify is None:
        flash('非管理员用户')
        return redirect(url_for('home'))

    if request.method == 'POST':
        tool_name = request.form['tool_name']
        tool_profile = request.form['tool_profile']

        new_tool = Tool(ToolName=tool_name, ToolProfile=tool_profile)
        db.session.add(new_tool)
        db.session.commit()

        # 处理上传的图片
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = "temp." + secure_filename(file.filename)
            if '.' in filename:
                tool_id = new_tool.ToolID
                file_extension = filename.rsplit('.', 1)[1].lower()
                destination_filename = f"{tool_id}.{file_extension}"
                file_path = 'pic/tool/' + destination_filename
                img = Image.open(file.stream)
                img.save('./static/' + file_path)

                # 更新路径
                new_tool.ToolPic = file_path
            else:
                flash('上传的文件缺少扩展名，请选择正确的图片文件')
        else:
            flash('上传的文件类型无效或者没有选定文件')

        db.session.commit()
        flash('新道具创建成功')
        return redirect(url_for('tools'))

    return render_template('new_tool.html')


@app.route('/forums')
def forums():
    # 检查用户是否已经登录
    if 'user_id' not in session:
        return redirect(url_for('login'))

    forums = Forum.query.all()
    forums_data = []
    for forum in forums:
        # 联合查询 Remark 和 User 表，以获取发言及其发言人的用户名
        remarks = db.session.query(Remark, User.UserName).join(User, Remark.UserID == User.UserID).filter(
            Remark.ForumID == forum.ForumID).order_by(Remark.RemarkID.desc()).limit(2).all()
        # SELECT Remark.*, User.UserName
        # FROM Remark
        # JOIN User ON Remark.UserID = User.UserID
        # WHERE Remark.ForumID = forum.ForumID
        # ORDER BY Remark.RemarkID DESC
        # LIMIT 2;

        # 将查询结果处理成字典列表，包含发言信息和用户名
        remarks_with_usernames = [{
            'remark_id': remark.RemarkID,
            'remark_content': remark.RemarkContent,
            'remark_time': remark.RemarkTime,
            'username': username
        } for remark, username in remarks]

        forums_data.append({
            'forum_id': forum.ForumID,
            'forum_name': forum.ForumName,
            'forum_profile': forum.ForumProfile,
            'latest_remarks': remarks_with_usernames  # 使用包含用户名的发言信息
        })
    return render_template('forums.html', forums=forums_data, current_user=get_user_info())


@app.route('/forum/<int:forum_id>', methods=['GET', 'POST'])
def forum_details(forum_id):
    # 检查用户是否已经登录
    if 'user_id' not in session:
        return redirect(url_for('login'))

    forum = Forum.query.get_or_404(forum_id)
    if request.method == 'POST':
        # 从表单获取发言内容
        remark_content = request.form.get('remark_content')
        if remark_content:
            # 创建Remark对象并保存到数据库
            new_remark = Remark(ForumID=forum_id, UserID=session.get('user_id'), RemarkContent=remark_content,
                                RemarkTime=datetime.utcnow())
            db.session.add(new_remark)
            db.session.commit()
            flash('Your remark has been posted.')
            return redirect(url_for('forum_details', forum_id=forum_id))
        else:
            flash('Remark content cannot be empty.')

    # 联合查询，以获取发言及其用户的用户名
    remarks = db.session.query(Remark, User.UserName).join(User, Remark.UserID == User.UserID).filter(
        Remark.ForumID == forum_id).order_by(Remark.RemarkID.desc()).all()
    # SELECT Remark.*, User.UserName
    # FROM Remark
    # JOIN User ON Remark.UserID = User.UserID
    # WHERE Remark.ForumID = forum_id
    # ORDER BY Remark.RemarkID DESC;

    # 将查询结果处理成字典列表，包含发言信息和用户名
    remarks_with_usernames = [{
        'remark_id': remark.RemarkID,
        'remark_content': remark.RemarkContent,
        'remark_time': remark.RemarkTime,
        'username': username
    } for remark, username in remarks]

    return render_template('forum_details.html', forum=forum, remarks=remarks_with_usernames,
                           current_user=get_user_info())


@app.route('/add_to_favorites/<int:piece_id>', methods=['POST'])
def add_to_favorites(piece_id):
    if 'user_id' not in session:
        flash('您需要登录才能进行收藏。')
        return redirect(url_for('login'))

    user_id = session['user_id']
    existing_save = Save.query.filter_by(UserID=user_id, PieceID=piece_id).first()
    # SELECT * FROM Save WHERE UserID = user_id AND PieceID = piece_id LIMIT 1;

    if existing_save:
        flash('您已经收藏过这个作品了。')
    else:
        new_save = Save(UserID=user_id, PieceID=piece_id)
        db.session.add(new_save)
        db.session.commit()
        flash('作品已成功添加到您的收藏中。')

    return redirect(request.referrer or url_for('piece_details'))


@app.route('/favorites')
def favorites():
    if 'user_id' not in session:
        flash('您需要登录才能查看收藏。')
        return redirect(url_for('login'))

    user_id = session['user_id']
    page_num = int(request.args.get('page', 1))
    PER_PAGE = 35
    favorites = db.session.query(Piece, Save).join(Save, Piece.PieceID == Save.PieceID).filter(
        Save.UserID == user_id).paginate(page=page_num, per_page=PER_PAGE)
    # SELECT Piece.*, Save.*
    # FROM Piece
    # JOIN Save ON Piece.PieceID = Save.PieceID
    # WHERE Save.UserID = user_id
    # LIMIT PER_PAGE OFFSET (page_num - 1) * PER_PAGE;

    favorites_list = [{
        'piece_id': piece.PieceID,
        'piece_name': piece.PieceName,
        'piece_type': piece.PieceType,
        'piece_profile': piece.PieceProfile,
        'piece_pic': piece.PiecePic,
        'piece_author': piece.PieceAuthor,
        'piece_os': piece.PieceOS,
        'piece_link': piece.PieceLink
    } for piece, save in favorites]

    return render_template('favorites.html', favorites=favorites_list, current_user=get_user_info())


@app.route('/remove_from_favorites/<int:piece_id>', methods=['POST'])
def remove_from_favorites(piece_id):
    if 'user_id' not in session:
        flash('您需要登录才能取消收藏。')
        return redirect(url_for('login'))

    user_id = session['user_id']
    save = Save.query.filter_by(UserID=user_id, PieceID=piece_id).first()
    if save:
        db.session.delete(save)
        db.session.commit()
        flash('作品已从您的收藏中移除。')
    else:
        flash('作品未在您的收藏中。')

    return redirect(url_for('favorites'))


@app.route('/rolelink', methods=['GET', 'POST'])
def rolelink():
    if 'user_id' not in session or not AdminUser.query.get_or_404(session['user_id']).AdminIdentify:
        flash('非管理员用户')
        return redirect(url_for('login'))

    pieces = Piece.query.all()
    roles = Role.query.all()

    if request.method == 'POST':
        piece_id = request.form['piece_id']
        role_id = request.form['role_id']
        new_rolelink = RoleLink(PieceID=piece_id, RoleID=role_id)
        db.session.add(new_rolelink)
        db.session.commit()
        flash('新角色关联创建成功')
        return redirect(url_for('rolelink'))

    return render_template('rolelink.html', pieces=pieces, roles=roles, current_user=get_user_info())


@app.route('/toollink', methods=['GET', 'POST'])
def toollink():
    if 'user_id' not in session or not AdminUser.query.get_or_404(session['user_id']).AdminIdentify:
        flash('非管理员用户')
        return redirect(url_for('login'))

    pieces = Piece.query.all()
    tools = Tool.query.all()

    if request.method == 'POST':
        piece_id = request.form['piece_id']
        tool_id = request.form['tool_id']
        new_toollink = ToolLink(PieceID=piece_id, ToolID=tool_id)
        db.session.add(new_toollink)
        db.session.commit()
        flash('新道具关联创建成功')
        return redirect(url_for('toollink'))

    return render_template('toollink.html', pieces=pieces, tools=tools, current_user=get_user_info())


@app.route('/admin')
def user_remarks():
    if 'user_id' not in session or not AdminUser.query.get_or_404(session['user_id']).AdminIdentify:
        flash('非管理员用户')
        return redirect(url_for('login'))

    sql = text('SELECT * FROM `user_remarks_view`')
    result = db.session.execute(sql)
    remarks = result.fetchall()

    # 将查询结果处理成字典列表
    remarks_list = [{
        'remark_id': row.RemarkID,
        'remark_content': row.RemarkContent,
        'remark_time': row.RemarkTime,
        'forum_id': row.ForumID,
        'user_id': row.UserID,
        'user_name': row.UserName,
        'forum_name': row.ForumName
    } for row in remarks]

    return render_template('admin.html', remarks=remarks_list)


@app.route('/unlinked_roles/<int:piece_id>')
def unlinked_roles(piece_id):
    if 'user_id' not in session:
        return jsonify([])

    roles = Role.query.outerjoin(RoleLink, (Role.RoleID == RoleLink.RoleID) & (RoleLink.PieceID == piece_id))\
                      .filter(RoleLink.PieceID == None).all()
    # SELECT Role.*
    # FROM Role
    # LEFT OUTER JOIN RoleLink ON Role.RoleID = RoleLink.RoleID AND RoleLink.PieceID = piece_id
    # WHERE RoleLink.PieceID IS NULL;

    roles_data = [{'RoleID': role.RoleID, 'RoleName': role.RoleName} for role in roles]
    return jsonify(roles_data)


@app.route('/unlinked_tools/<int:piece_id>')
def unlinked_tools(piece_id):
    if 'user_id' not in session:
        return jsonify([])

    tools = Tool.query.outerjoin(ToolLink, (Tool.ToolID == ToolLink.ToolID) & (ToolLink.PieceID == piece_id))\
                      .filter(ToolLink.PieceID == None).all()
    # SELECT Tool.*
    # FROM Tool
    # LEFT OUTER JOIN ToolLink ON Tool.ToolID = ToolLink.ToolID AND ToolLink.PieceID = piece_id
    # WHERE ToolLink.PieceID IS NULL;

    tools_data = [{'ToolID': tool.ToolID, 'ToolName': tool.ToolName} for tool in tools]
    return jsonify(tools_data)


@app.route('/rolelink/delete', methods=['GET', 'POST'])
def delete_rolelink():
    if 'user_id' not in session or not AdminUser.query.get(session['user_id']).AdminIdentify:
        flash('You must be an admin to view this page.')
        return redirect(url_for('login'))

    pieces = Piece.query.all()
    roles = []
    selected_piece_id = None

    if request.method == 'POST':
        selected_piece_id = request.form.get('piece_id')
        if selected_piece_id:
            roles = db.session.query(Role).join(RoleLink, Role.RoleID == RoleLink.RoleID).filter(
                RoleLink.PieceID == selected_piece_id).all()
            # SELECT Role.*
            # FROM Role
            # JOIN RoleLink ON Role.RoleID = RoleLink.RoleID
            # WHERE RoleLink.PieceID = selected_piece_id;

        role_id = request.form.get('role_id')
        if role_id:
            rolelink = RoleLink.query.filter_by(PieceID=selected_piece_id, RoleID=role_id).first()
            if rolelink:
                db.session.delete(rolelink)
                db.session.commit()
                flash('角色关联删除成功')
                return redirect(url_for('delete_rolelink'))

    return render_template('delete_rolelink.html', pieces=pieces, roles=roles, selected_piece_id=selected_piece_id,
                           current_user=get_user_info())


@app.route('/toollink/delete', methods=['GET', 'POST'])
def delete_toollink():
    if 'user_id' not in session or not AdminUser.query.get_or_404(session['user_id']).AdminIdentify:
        flash('You must be an admin to view this page.')
        return redirect(url_for('login'))

    pieces = Piece.query.all()
    tools = []
    selected_piece_id = None

    if request.method == 'POST':
        selected_piece_id = request.form.get('piece_id')
        if selected_piece_id:
            tools = db.session.query(Tool).join(ToolLink, Tool.ToolID == ToolLink.ToolID).filter(
                ToolLink.PieceID == selected_piece_id).all()
            # SELECT Tool.*
            # FROM Tool
            # JOIN ToolLink ON Tool.ToolID = ToolLink.ToolID
            # WHERE ToolLink.PieceID = selected_piece_id;

        tool_id = request.form.get('tool_id')
        if tool_id:
            toollink = ToolLink.query.filter_by(PieceID=selected_piece_id, ToolID=tool_id).first()
            if toollink:
                db.session.delete(toollink)
                db.session.commit()
                flash('道具关联删除成功')
                return redirect(url_for('delete_toollink'))

    return render_template('delete_toollink.html', pieces=pieces, tools=tools, selected_piece_id=selected_piece_id,
                           current_user=get_user_info())



if __name__ == "__main__":
    with app.app_context():
        # db.drop_all()
        db.create_all()
    app.run(debug=True)
