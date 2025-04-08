from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from flask_socketio import SocketIO
from flask_socketio import emit
from flask_socketio import join_room
import jwt
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'm7u2p$9a1r!b#x@z&k8w'
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:Bhmk7gh90r@localhost:5432/MTAAskuska'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

socketio = SocketIO(app, cors_allowed_origins='*')

class UserTeam(db.Model):
    __tablename__ = 'user_teams'
    team_id = db.Column(db.Integer, db.ForeignKey('teams.id'), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    role = db.Column(db.String(50))

class Team(db.Model):
    __tablename__ = 'teams'
    id = db.Column(db.Integer, primary_key=True )
    name = db.Column(db.String(100), nullable=False)
    creator_id = db.Column(db.Integer, db.ForeignKey('users.id'))

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
class Invitation(db.Model):
    __tablename__ = 'invitations'
    id = db.Column(db.Integer, primary_key=True)
    team_id = db.Column(db.Integer, db.ForeignKey('teams.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')

class Project(db.Model):
    __tablename__ = 'projects'
    id = db.Column(db.Integer, primary_key=True)
    project_name = db.Column(db.String(100), nullable=False)
    team_id = db.Column(db.Integer, db.ForeignKey('teams.id'), nullable=False)
    deadline = db.Column(db.DateTime, nullable=True)

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    team_id = db.Column(db.Integer, db.ForeignKey('teams.id'), nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)

class Task(db.Model):
    __tablename__ = 'tasks'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    completed = db.Column(db.Boolean, default=False)
    deadline = db.Column(db.DateTime, nullable=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)
    parent_task_id = db.Column(db.Integer, db.ForeignKey('tasks.id'), nullable=True)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]

        if not token:
            return jsonify({'error': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(data['user_id'])
            if not current_user:
                raise Exception('User not found')
        except Exception as e:
            return jsonify({'error': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated



@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    new_user = User(username=data['username'], email=data['email'])
    new_user.set_password(data['password'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User registered successfully!"}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    if user and user.check_password(data['password']):
        token = jwt.encode({
            'user_id': user.id,
            'exp': datetime.utcnow() + timedelta(hours=6)
        }, app.config['SECRET_KEY'], algorithm='HS256')

        return jsonify({
            "message": "Login successful!",
            "token": token,
            "userID": user.id
        }), 200
    else:
        return jsonify({"error": "Invalid email or password"}), 401



@app.route('/getTeams', methods=['GET'])
def get_teams():
    user_id = request.args.get('userID', type=int)
    if user_id is None:
        return jsonify({"error": "userID is required"}), 400

    results = db.session.query(Team).join(UserTeam, Team.id == UserTeam.team_id)\
        .filter(UserTeam.user_id == user_id).all()

    teams = []
    for team in results:
        teams.append({
            "id": team.id,
            "name": team.name,
            "creator_id": team.creator_id
        })

    return jsonify(teams), 200


@app.route('/createTeam', methods=['POST'])
def create_team():
    data = request.get_json()
    name = data.get('name')
    description = data.get('description')
    user_id = data.get('user_id')
    member_emails = data.get('members', [])

    if not name or not user_id:
        return jsonify({"message": "Missing name or user ID"}), 400

    new_team = Team(name=name, creator_id=user_id)
    db.session.add(new_team)
    db.session.commit()

    owner_entry = UserTeam(team_id=new_team.id, user_id=user_id, role="owner")
    db.session.add(owner_entry)

    for email in member_emails:
        user = User.query.filter_by(email=email).first()
        if user:
            invitation = Invitation(team_id=new_team.id, user_id=user.id, status='pending')
            db.session.add(invitation)
        else:
            print(f"User with email {email} not found, skipping invitation.")
    db.session.commit()

    return jsonify({"message": "Team created successfully!"}), 201

@app.route('/getInvitations', methods=['Get'])
def get_invitations():
    user_id = request.args.get('userId', type=int)

    if user_id is None:
        return jsonify({"error": "Missing userID"}), 400

    invitations = db.session.query(
        Invitation.id.label('invite_id'),
        Team.name.label('team_name'),
        User.username.label('creator_name')
    ).join(Team, Invitation.team_id == Team.id)\
     .join(User, Team.creator_id == User.id)\
     .filter(Invitation.user_id == user_id, Invitation.status == 'pending')\
     .all()

    invite_list = []
    for invite in invitations:
        invite_list.append({
            "invite_id": invite.invite_id,
            "team_name": invite.team_name,
            "sender_name": invite.creator_name
        })
    
    return jsonify(invite_list), 200

@app.route('/acceptInvite', methods=['POST'])
def accept_invite():
    data = request.get_json()
    invite_id =data.get('invite_id')

    invitation = Invitation.query.filter_by(id=invite_id).first()

    if not invitation:
        return jsonify({"error": "Invitation not found"}), 404
    
    if invitation.status != 'pending':
        return jsonify({"error": "Ivitation already handled"}), 400
    
    new_link = UserTeam(team_id=invitation.team_id, user_id=invitation.user_id, role='member')
    db.session.add(new_link)

    invitation.status = 'accepted'
    db.session.commit()

    return jsonify({"message": "Invitation accepted and user added to team"}), 200

@app.route('/declineInvite', methods=['POST'])
def decline_invite():
    data = request.get_json()
    invite_id =data.get('invite_id')

    invitation = Invitation.query.filter_by(id=invite_id).first()

    if not invitation:
        return jsonify({"error": "Invitation not found"}), 404
    
    if invitation.status != 'pending':
        return jsonify({"error": "Ivitation already handled"}), 400
    
    invitation.status = 'declined'
    db.session.commit()

    return jsonify({"message": "Invitation declined"}), 200


@app.route('/getProjects', methods=['GET'])
def get_projects():
    team_id = request.args.get('teamID', type=int)

    if team_id is None:
        return jsonify({"error": "teamID is required"}), 400

    projects = db.session.query(Project).filter_by(team_id=team_id).all()

    project_list = []
    for project in projects:
        project_list.append({
            "id": project.id,
            "project_name": project.project_name,
            "team_id": project.team_id,
            "deadline": project.deadline.isoformat() if project.deadline else None
        })

    return jsonify(project_list), 200

@app.route('/createProject', methods=['POST'])
def create_project():
    data = request.get_json()
    project_name = data.get('name')
    deadline = data.get('deadline')
    team_id = data.get('team_id')
    if not project_name or not team_id:
        return jsonify({"error": "Missing project name or team ID"}), 400

    try:
        team_id = int(team_id)
    except ValueError:
        return jsonify({"error": "Invalid team ID"}), 400

    new_project = Project(project_name=project_name, team_id=team_id, deadline=deadline)
    db.session.add(new_project)
    db.session.commit()

    return jsonify({"message": "Project created successfully!"}), 201

@app.route('/getTeamMembers', methods=['GET'])
def get_team_members():
    team_id = request.args.get('teamID', type=int)

    if team_id is None:
        return jsonify({"error": "teamID is required"}), 400

    members = db.session.query(
        User.id.label('user_id'),
        User.username.label('username'),
        User.email.label('email'),
        UserTeam.role.label('role')
    ).join(UserTeam, User.id == UserTeam.user_id)\
        .filter(UserTeam.team_id == team_id).all()

    member_list = []
    for member in members:
        member_list.append({
            "user_id": member.user_id,
            "username": member.username,
            "email": member.email,
            "role": member.role
        })

    return jsonify(member_list), 200

@app.route('/setInvite', methods=['POST'])
def set_invite():
    data = request.get_json()
    email = data.get('email')
    team_id = data.get('team')

    if not email or not team_id:
        return jsonify({"error": "Missing email or team ID"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User with the provided email not found"}), 404

    try:
        team_id = int(team_id)
    except ValueError:
        return jsonify({"error": "Invalid team ID"}), 400

    new_invitation = Invitation(team_id=team_id, user_id=user.id, status='pending')
    db.session.add(new_invitation)
    db.session.commit()

    return jsonify({"message": "Invitation created successfully!"}), 201

@socketio.on('join')
def on_join(data):
    team_id = data.get('team_id')
    join_room(f"team_{team_id}")

@socketio.on('send_message')
def handle_message(data):
    sender_id = data['sender_id']
    team_id = data['team_id']
    content = data['content']

    user = User.query.get(sender_id)
    sender_name = user.username if user else "Unknwon"

    msg = Message(user_id=sender_id, team_id=team_id, message=content)
    db.session.add(msg)
    db.session.commit()

    room = f"team_{team_id}"
    emit('receive_message', {
        'sender_id': sender_id,
        'team_id': team_id,
        'content': content,
        'date': msg.date.isoformat(),
    }, room=room)

@app.route('/getMessages', methods=['GET'])
def get_messages():
    team_id = request.args.get('teamID', type=int)
    offset = request.args.get('offset', default=0, type=int)
    limit = request.args.get('limit', default=20, type=int)

    if not team_id:
        return jsonify({"error": "Missing teamID"}), 400
    
    messages = db.session.query(Message, User.username)\
        .join(User, Message.user_id == User.id)\
        .filter(Message.team_id == team_id)\
        .order_by(Message.date.desc())\
        .offset(offset)\
        .limit(limit)\
        .all()
    
    result = [{
        "id": msg.Message.id,
        "content": msg.Message.message,
        "sender_id": msg.Message.user_id,
        "sender_name": msg.username,
        "team_id": msg.Message.team_id,
        "date": msg.Message.date.isoformat()
    } for msg in reversed(messages)]

    return jsonify(result), 200

@app.route('/getProjectTasks', methods=['GET'])
def get_project_tasks():
    project_id = request.args.get('projectID', type=int)

    if project_id is None:
        return jsonify({"error": "projectID is required"}), 400

    tasks = db.session.query(Task).filter_by(project_id=project_id).all()

    task_list = []
    for task in tasks:
        task_list.append({
            "id": task.id,
            "name": task.name,
            "description": task.description,
            "completed": task.completed,
            "deadline": task.deadline.isoformat() if task.deadline else None,
            "parent_task_id": task.parent_task_id
        })

    return jsonify(task_list), 200

@app.route('/removeTeamMember', methods=['DELETE'])
@token_required
def remove_team_member(current_user):
    data = request.get_json()
    user_id = data.get('user_id')
    team_id = data.get('team_id')

    if not user_id or not team_id:
        return jsonify({"error": "Missing user_id or team_id"}), 400

    user_team = UserTeam.query.filter_by(user_id=user_id, team_id=team_id).first()

    if not user_team:
        return jsonify({"error": "User is not a member of the team"}), 404

    db.session.delete(user_team)
    db.session.commit()

    return jsonify({"message": "User removed from the team successfully"}), 200

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
