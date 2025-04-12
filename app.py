from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from flask_socketio import SocketIO
from flask_socketio import emit
from flask_socketio import join_room
import jwt
import requests
from functools import wraps
from flasgger import Swagger
import firebase_admin
from firebase_admin import credentials, messaging
import random
import smtplib
from email.mime.text import MIMEText

app = Flask(__name__)
app.config['SECRET_KEY'] = 'm7u2p$9a1r!b#x@z&k8w'
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:Bhmk7gh90r@localhost:5432/MTAAskuska'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
swagger = Swagger(app)

db = SQLAlchemy(app)

socketio = SocketIO(app, cors_allowed_origins='*')

cred = credentials.Certificate("mtaaprojekt-b3546464b2d5.json")
firebase_admin.initialize_app(cred)
SMTP_EMAIL="mtaaprojekt@gmail.com"
SMTP_PASSWORD="vjos ulgj qkyw kzf"


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
    assigned_to = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)
    parent_task_id = db.Column(db.Integer, db.ForeignKey('tasks.id'), nullable=True)

class DeviceToken(db.Model):
    __tablename__ = 'device_tokens'
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(255), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('device_tokens', lazy=True))

class PasswordResetCode(db.Model):
    __tablename__ = 'password_reset_codes'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

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
    """
    Register a new user
    ---
    tags:
      - Auth
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - username
            - email
            - password
          properties:
            username:
              type: string
            email:
              type: string
            password:
              type: string
    responses:
      201:
        description: User registered successfully
      400:
        description: Email already exists
    """
    data = request.get_json()
    existing_user = User.query.filter_by(email=data['email']).first()
    if existing_user:
        return jsonify({"error": "User with this email already exists"}), 400

    new_user = User(username=data['username'], email=data['email'])
    new_user.set_password(data['password'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User registered successfully!"}), 201


@app.route('/login', methods=['POST'])
def login():
    """
    Authenticate user and return a JWT token
    ---
    tags:
      - Auth
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - email
            - password
          properties:
            email:
              type: string
            password:
              type: string
    responses:
      200:
        description: Login successful
      401:
        description: Invalid credentials
    """
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
    """
    Get all teams for a user
    ---
    tags:
      - Teams
    parameters:
      - name: userID
        in: query
        type: integer
        required: true
        description: ID of the user
    responses:
      200:
        description: List of teams
    """
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
    """
    Create a new team and send invitations
    ---
    tags:
      - Teams
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - name
            - user_id
          properties:
            name:
              type: string
            description:
              type: string
            user_id:
              type: integer
            members:
              type: array
              items:
                type: string
    responses:
      201:
        description: Team created successfully
      400:
        description: Missing name or user ID
    """

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

@app.route('/getInvitations', methods=['GET'])
def get_invitations():
    """
    Get pending invitations for a user
    ---
    tags:
      - Invitations
    parameters:
      - name: userId
        in: query
        type: integer
        required: true
        description: User ID to fetch invitations
    responses:
      200:
        description: List of pending invitations
    """

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
    """
    Accept a team invitation
    ---
    tags:
      - Invitations
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - invite_id
          properties:
            invite_id:
              type: integer
    responses:
      200:
        description: Invitation accepted and user added to team
      404:
        description: Invitation not found
      400:
        description: Invitation already handled
    """

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
    """
    Decline a team invitation
    ---
    tags:
      - Invitations
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - invite_id
          properties:
            invite_id:
              type: integer
    responses:
      200:
        description: Invitation declined
      404:
        description: Invitation not found
      400:
        description: Invitation already handled
    """

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
    """
    Get all projects for a team
    ---
    tags:
      - Projects
    parameters:
      - name: teamID
        in: query
        type: integer
        required: true
        description: ID of the team
    responses:
      200:
        description: List of projects
    """

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
    """
    Create a new project
    ---
    tags:
      - Projects
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - name
            - team_id
          properties:
            name:
              type: string
            deadline:
              type: string
              format: date-time
            team_id:
              type: integer
    responses:
      201:
        description: Project created successfully
      400:
        description: Missing project name or team ID
    """

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
    """
    Get all members of a team
    ---
    tags:
      - Teams
    parameters:
      - name: teamID
        in: query
        type: integer
        required: true
        description: Team ID
    responses:
      200:
        description: List of team members
    """

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
    """
    Send invitation to a user via email
    ---
    tags:
      - Invitations
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - email
            - team
          properties:
            email:
              type: string
            team:
              type: integer
    responses:
      201:
        description: Invitation created successfully
      400:
        description: Missing email or team ID
      404:
        description: User with provided email not found
    """

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

    fcm_tokens = get_active_tokens_for_team(team_id, exclude_user_id=sender_id)
    send_push_notification(
        fcm_tokens,
        title=f"Message from {sender_name}",
        body=content[:100] + ("..." if len(content) > 100 else ""),
        data={"team_id": str(team_id), "type": "chat_message"}
    )

@app.route('/getMessages', methods=['GET'])
def get_messages():
    """
    Get messages for a team
    ---
    tags:
      - Messages
    parameters:
      - name: teamID
        in: query
        type: integer
        required: true
        description: Team ID
      - name: offset
        in: query
        type: integer
        required: false
        description: Pagination offset
      - name: limit
        in: query
        type: integer
        required: false
        description: Max messages to return
    responses:
      200:
        description: List of messages
    """

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
    """
    Get all tasks for a project
    ---
    tags:
      - Tasks
    parameters:
      - name: projectID
        in: query
        type: integer
        required: true
        description: ID of the project
    responses:
      200:
        description: List of tasks
    """

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
            "assigned_to": task.assigned_to,
            "deadline": task.deadline.isoformat() if task.deadline else None,
            "parent_task_id": task.parent_task_id
        })

    return jsonify(task_list), 200

@app.route('/removeTeamMember', methods=['DELETE'])
@token_required
def remove_team_member(current_user):
    """
    Remove a user from a team
    ---
    tags:
      - Teams
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - user_id
            - team_id
          properties:
            user_id:
              type: integer
            team_id:
              type: integer
    responses:
      200:
        description: User removed successfully
      400:
        description: Missing user_id or team_id
      404:
        description: User is not a member
    """

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

@app.route('/createTask', methods=['POST'])
@token_required
def create_task(current_user):
    """
    Create a task in a project
    ---
    tags:
      - Tasks
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - name
            - project_id
          properties:
            name:
              type: string
            description:
              type: string
            assign:
              type: integer
            deadline:
              type: string
              format: date-time
            project_id:
              type: integer
            parent_task_id:
              type: integer
    responses:
      201:
        description: Task created successfully
      400:
        description: Missing task name or project ID
    """

    data = request.get_json()
    name = data.get('name')
    description = data.get('description')
    assigned_to = data.get('assign')
    deadline = data.get('deadline')
    project_id = data.get('project_id')
    parent_task_id = data.get('parent_task_id')

    if not name or not project_id:
        return jsonify({"error": "Missing task name or project ID"}), 400

    try:
        project_id = int(project_id)
        if assigned_to:
            assigned_to = int(assigned_to)
        if parent_task_id:
            parent_task_id = int(parent_task_id)
    except ValueError:
        return jsonify({"error": "Invalid project ID, assigned_to, or parent_task_id"}), 400

    new_task = Task(
        name=name,
        description=description,
        assigned_to=assigned_to,
        deadline=deadline,
        completed=False,
        project_id=project_id,
        parent_task_id=parent_task_id
    )
    db.session.add(new_task)
    db.session.commit()

    return jsonify({"message": "Task created successfully!", "task_id": new_task.id}), 201

@app.route('/register_token', methods=['POST'])
@token_required
def register_token(current_user):
    """
    Register or reactivate an FCM token for the current user
    ---
    tags:
      - Notifications
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - token
          properties:
            token:
              type: string
              description: The FCM device token to register or reactivate
    responses:
      200:
        description: FCM token registered or reactivated
      400:
        description: Token is required
    """

    data = request.get_json()
    token = data.get('token')

    if not token:
        return jsonify({'error': 'Token is required'}), 400
    
    existing = DeviceToken.query.filter_by(token=token).first()

    if existing:
        existing.user_id = current_user.id
        existing.is_active = True
    else:
        new_token = DeviceToken(token=token, user_id=current_user.id, is_active=True)
        db.session.add(new_token)

    db.session.commit()

    return jsonify({'message': 'FCM token registered or reactivated'}), 200


@app.route('/device_token/<string:token>', methods=['PUT'])
@token_required
def update_device_token(current_user, token):
    """
    Update FCM device token status (activate/deactivate)
    ---
    tags:
      - Notifications
    parameters:
      - name: token
        in: path
        required: true
        type: string
        description: The FCM token to update
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - is_active
          properties:
            is_active:
              type: boolean
              description: Whether the token is active (True) or deactivated (False)
    responses:
      200:
        description: Token updated successfully
      400:
        description: Missing is_active value
      404:
        description: Token not found
    """
    data = request.get_json()
    is_active = data.get('is_active')

    if is_active is None:
        return jsonify({'error': 'Missing is-active value'}), 400
    
    token_record = DeviceToken.query.filter_by(token=token, user_id=current_user.id).first()

    if not token_record:
        return jsonify({'error': 'Token not found'}), 404
    
    token_record.is_active = is_active
    token_record.update_at = datetime.utcnow()

    db.session.commit()

    return jsonify({'message': 'Token updated successfully'}), 200

def get_active_tokens_for_team(team_id, exclude_user_id=None):
    query = db.session.query(DeviceToken.token)\
        .join(UserTeam, DeviceToken.user_id == UserTeam.user_id)\
        .filter(UserTeam.team_id == team_id, DeviceToken.is_active == True)

    if exclude_user_id:
        query = query.filter(DeviceToken.user_id != exclude_user_id)

    return [row.token for row in query.all()]

def send_push_notification(fcm_tokens, title, body, data=None):
    if not fcm_tokens:
        return

    notification = messaging.Notification(
        title=title,
        body=body
    )

    android_config = messaging.AndroidConfig(
        priority='high',
        notification=messaging.AndroidNotification(
            sound='default'
        )
    )

    message = messaging.MulticastMessage(
        tokens=fcm_tokens,
        notification=notification,
        data={k: str(v) for k, v in (data or {}).items()},
        android=android_config,
    )

    response = messaging.send_multicast(message)

    print(f"Successfully sent {response.success_count} messages, {response.failure_count} failed.")
    if response.failure_count > 0:
        for idx, resp in enumerate(response.responses):
            if not resp.success:
                print(f"Failure for token {fcm_tokens[idx]}: {resp.exception}")

@app.route('/modifyTaskStatus', methods=['PUT'])
@token_required
def modify_task_status(current_user):
    """
    Modify the status of a task
    ---
    tags:
        - Tasks
    parameters:
        - in: body
        name: body
        required: true
        schema:
            type: object
            required:
            - task_id
            - completed
            properties:
            task_id:
                type: integer
            completed:
                type: boolean
    responses:
        200:
        description: Task status updated successfully
        400:
        description: Missing task_id or completed status
        404:
        description: Task not found
    """
    data = request.get_json()
    task_id = data.get('task_id')
    completed = data.get('completed')

    if task_id is None or completed is None:
        return jsonify({"error": "Missing task_id or completed status"}), 400

    task = Task.query.filter_by(id=task_id).first()

    if not task:
        return jsonify({"error": "Task not found"}), 404

    task.completed = completed
    db.session.commit()

    return jsonify({"message": "Task status updated successfully"}), 200

def send_reset_email(email, code):
    sender_email = SMTP_EMAIL
    sender_password = SMTP_PASSWORD
    smtp_server = "smtp.gmail.com"
    smtp_port = 587

    subejct = "Your Password Reset Code"
    body = f"Here is your password reset code: {code}"

    msg = MIMEText(body)
    msg['Subject'] = subejct
    msg['From'] = sender_email
    msg['To'] = email

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendd_message(msg)

    print(f"Reset code sent to {email}")


@app.route('/requestPasswordReset', methods=['POST'])
def request_password_reset():
    """
    Request a password reset code via email
    ---
    tags:
      - Auth
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - email
          properties:
            email:
              type: string
    responses:
      200:
        description: Code sent if user exists
      400:
        description: Email is required
    """
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({'error': 'Email is required'}), 400
    
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'If the email exists, a reset code has been sent.'}), 200
    
    code = str(random.randint(100000, 999999))

    reset_entry = PasswordResetCode(email=email, code=code)
    db.session.add(reset_entry)
    db.session.commit()

    try:
        send_reset_email(email, code)
    except Exception as e:
        print(f"Error sending email. {e}")
        return jsonify({'error': 'Failed to send reset email'}), 500
    
    return jsonify({'message': 'If the email exists, a reset code has been sent.'}), 200

@app.route('/verifyResetCode', methods=['POST'])
def verify_reset_code():
    """
    Verify password reset code
    ---
    tags:
      - Auth
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - email
            - code
          properties:
            email:
              type: string
            code:
              type: string
    responses:
      200:
        description: Code verified successfully
      400:
        description: Invalid or expired code
    """
    data = request.get_json()
    email = data.get('email')
    code = data.get('code')

    if not email or not code:
        return jsonify({'error': 'Email and code are required'}), 400
    
    entry = PasswordResetCode.query.filter_by(email=email, code=code)\
      .order_by(PasswordResetCode.created_at.desc()).first()
    
    time_diff = datetime.utcnow() - entry.created_at
    if time_diff.total_seconds() > 900:
        return jsonify({'error': 'Code expired'}), 400
    
    return jsonify({'message': 'Code verified'}), 200

@app.route('/resetPassword', methods=['PUT'])
def reset_password():
    """
    Reset password with a verified reset code
    ---
    tags:
      - Auth
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - email
            - code
            - new_password
          properties:
            email:
              type: string
            code:
              type: string
            new_password:
              type: string
    responses:
      200:
        description: Password reset successful
      400:
        description: Invalid or expired code
      404:
        description: User not found
    """
    data = request.get_json()
    email = data.get('email')
    code = data.get('code')
    new_password = data.get('new_password')

    if not email or not code or not new_password:
        return jsonify({'error': 'Missing email, code or new password'}), 400

    reset_entry = PasswordResetCode.query.filter_by(email=email, code=code)\
      .order_by(PasswordResetCode.created_at.desc()).first()
    
    if not reset_entry:
        return jsonify({'error': 'Invalid code'}), 400
    
    if (datetime.utcnow() - reset_entry.created_at).total_seconds() > 900:
        return jsonify({'error': 'Code expired'}), 400
    
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    user.set_password(new_password)
    db.session.commit()

    db.session.delete(reset_entry)
    db.session.commit()

    return jsonify({'message': 'Password has been reset successfully'}), 200


if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
