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
import json
import requests
from google.oauth2 import service_account
import google.auth.transport.requests

import random
import smtplib
from email.mime.text import MIMEText
SERVICE_ACCOUNT_FILE = 'mtaa2-c6f5e-firebase-adminsdk-fbsvc-2af0600069.json'
FCM_ENDPOINT = 'https://fcm.googleapis.com/v1/projects/mtaa2-c6f5e/messages:send'
app = Flask(__name__)
app.config['SECRET_KEY'] = 'm7u2p$9a1r!b#x@z&k8w'
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:Bhmk7gh90r@localhost:5432/MTAAskuska'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

swagger_template = {
    "swagger": "2.0",
    "info": {
        "title": "MTAA API",
        "description": "API pre správu tímov, projektov a úloh",
        "version": "1.0"
    },
    "securityDefinitions": {
        "Bearer": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": "Zadaj token vo formáte **Bearer &lt;token&gt;**"
        }
    },
    "security": [{"Bearer": []}]
}

swagger = Swagger(app, template=swagger_template)

db = SQLAlchemy(app)

socketio = SocketIO(app, cors_allowed_origins='*')

SMTP_EMAIL="jan2003porubsky@gmail.com"
SMTP_PASSWORD="nszu ohwv wnks fpvr"


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
    team_description = db.Column(db.String, nullable=False, default="No description")

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    profile_picture = db.Column(db.LargeBinary, nullable=True)
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

def permission_required(f):
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        data = request.get_json()
        task_id = data.get('task_id')
        team_id = data.get('team_id')
        project_id = data.get('project_id')

        if task_id:
            task = Task.query.filter_by(id=task_id).first()
            if not task:
                return jsonify({"error": "Task not found"}), 404

            project = Project.query.filter_by(id=task.project_id).first()
            if not project:
                return jsonify({"error": "Project not found"}), 404

            current_task = task
            while current_task:
                if current_task.assigned_to == current_user.id:
                    break
                current_task = Task.query.filter_by(id=current_task.parent_task_id).first()
            else:
                user_team = UserTeam.query.filter_by(user_id=current_user.id, team_id=project.team_id).first()
                if not user_team or user_team.role not in ['admin', 'owner']:
                    return jsonify({"error": "Permission denied"}), 403
        if team_id:
            user_team = UserTeam.query.filter_by(user_id=current_user.id, team_id=team_id).first()
            if not user_team or user_team.role not in ['admin', 'owner']:
                return jsonify({"error": "Permission denied"}), 403

        if project_id:
            project = Project.query.filter_by(id=project_id).first()
            if not project:
                return jsonify({"error": "Project not found"}), 404

            user_team = UserTeam.query.filter_by(user_id=current_user.id, team_id=project.team_id).first()
            if not user_team or user_team.role not in ['admin', 'owner']:
                return jsonify({"error": "Permission denied"}), 403

        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/register', methods=['POST'])
def register():
    """
    Register a new user
    ---
    tags:
      - Auth
    security:
      - Bearer: []  
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
    security:
      - Bearer: [] 
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
          "userID": user.id,
          "username": user.username,
          "email": user.email,
          "profile_picture": user.profile_picture.decode() if user.profile_picture else None
      }), 200
    else:
      return jsonify({"error": "Invalid email or password"}), 401



@app.route('/getTeams', methods=['GET'])
@token_required
def get_teams(current_user):
    """
    Get all teams for a user
    ---
    tags:
      - Teams
    security:
      - Bearer: []
    parameters:
      - name: userID
        in: query
        type: integer
        required: true
        description: ID of the user
    responses:
      200:
        description: List of teams
        schema:
          type: array
          items:
            type: object
            properties:
              id:
                type: integer
                description: Team ID
              name:
                type: string
                description: Team name
              creator_id:
                type: integer
                description: ID of the team creator
              description:
                type: string
                description: Description of the team
      400:
        description: userID is required
      401:
        description: User not authorized to view these teams
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
            "creator_id": team.creator_id,
            "description": team.team_description
        })

    return jsonify(teams), 200


@app.route('/createTeam', methods=['POST'])
@token_required
def create_team(current_user):
    """
    Create a new team and send invitations
    ---
    tags:
      - Teams
    security:
      - Bearer: []
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
              description: Name of the team
            description:
              type: string
              description: Description of the team
            user_id:
              type: integer
              description: ID of the team creator (owner)
            members:
              type: array
              items:
                type: string
              description: List of emails to invite
    responses:
      201:
        description: Team created successfully
      400:
        description: Missing name or user ID
      401:
        description: User not authorized
    """

    data = request.get_json()
    name = data.get('name')
    description = data.get('description')
    user_id = data.get('user_id')
    member_emails = data.get('members', [])

    if not name or not user_id:
        return jsonify({"message": "Missing name or user ID"}), 400

    new_team = Team(name=name, creator_id=user_id, team_description=description or "No description")
    db.session.add(new_team)
    db.session.commit()

    owner_entry = UserTeam(team_id=new_team.id, user_id=user_id, role="owner")
    db.session.add(owner_entry)

    for email in member_emails:
        user = User.query.filter_by(email=email).first()
        print(email)
        if user:
            invitation = Invitation(team_id=new_team.id, user_id=user.id, status='pending')
            db.session.add(invitation)
        else:
            print(f"User with email {email} not found, skipping invitation.")
    db.session.commit()

    return jsonify({"message": "Team created successfully!","id": new_team.id}), 201

@app.route('/getInvitations', methods=['GET'])
@token_required
def get_invitations(current_user):
    """
    Get pending invitations for a user
    ---
    tags:
      - Invitations
    security:
      - Bearer: [] 
    parameters:
      - name: userId
        in: query
        type: integer
        required: true
        description: User ID to fetch invitations
    responses:
      200:
        description: List of pending invitations
      400:
        description: Missing userID
      401:
        description: User not authorized to view these invitations
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
@token_required
def accept_invite(current_user):
    """
    Accept a team invitation
    ---
    tags:
      - Invitations
    security:
      - Bearer: [] 
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
      401:
        description: User not authorized to accept this invitation
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
@token_required
def decline_invite(current_user):
    """
    Decline a team invitation
    ---
    tags:
      - Invitations
    security:
      - Bearer: [] 
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
      401:
        description: User not authorized to decline this invitation
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
@token_required
def get_projects(current_user):
    """
    Get all projects for a team
    ---
    tags:
      - Projects
    security:
      - Bearer: [] 
    parameters:
      - name: teamID
        in: query
        type: integer
        required: true
        description: ID of the team
    responses:
      200:
        description: List of projects
      400:
        description: Missing teamID
      401:
        description: User not authorized to view these projects
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
@token_required
@permission_required
def create_project(current_user):
    """
    Create a new project
    ---
    tags:
      - Projects
    security:
      - Bearer: [] 
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
      401:
        description: User not authorized
      403:
        description: User does not have permission to create projects in this team
       
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

    return jsonify({"message": "Project created successfully!", "id": new_project.id}), 201

@app.route('/getTeamMembers', methods=['GET'])
@token_required
def get_team_members(current_user):
    """
    Get all members of a team
    ---
    tags:
      - Teams
    security:
      - Bearer: [] 
    parameters:
      - name: teamID
        in: query
        type: integer
        required: true
        description: Team ID
    responses:
      200:
        description: List of team members
      400:
        description: Missing teamID
      401:
        description: User not authorized
    """

    team_id = request.args.get('teamID', type=int)

    if team_id is None:
        return jsonify({"error": "teamID is required"}), 400

    members = db.session.query(
        User.id.label('user_id'),
        User.username.label('username'),
        User.email.label('email'),
        User.profile_picture.label('profile_picture'),
        UserTeam.role.label('role')
    ).join(UserTeam, User.id == UserTeam.user_id)\
        .filter(UserTeam.team_id == team_id).all()

    member_list = []
    for member in members:
        member_list.append({
            "user_id": member.user_id,
            "username": member.username,
            "email": member.email,
            "role": member.role,
            "profile_picture": member.profile_picture.decode() if member.profile_picture else None
        })

    return jsonify(member_list), 200
@app.route('/setInvite', methods=['POST'])
@token_required
@permission_required
def set_invite(current_user):
    """
    Send invitation to a user via email
    ---
    tags:
      - Invitations
    security:
      - Bearer: [] 
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
      401:
        description: User not authorized to send invitations
      403:
        description: User does not have permission to send invitations
    """

    data = request.get_json()
    email = data.get('email')
    team_id = data.get('team_id')

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
  sender_name = user.username if user else "Unknown"

  team = Team.query.get(team_id)
  team_name = team.name if team else "Unknown Team"

  msg = Message(user_id=sender_id, team_id=team_id, message=content)
  db.session.add(msg)
  db.session.commit()

  room = f"team_{team_id}"
  emit('receive_message', {
    'sender_id': sender_id,
    'team_id': team_id,
    'team_name': team_name,
    'content': content,
    'date': msg.date.isoformat(),
  }, room=room)

  fcm_tokens = get_active_tokens_for_team(team_id, exclude_user_id=sender_id)
  send_push_notifications(
    fcm_tokens,
    title=f"Message from {sender_name}",
    body=content[:100] + ("..." if len(content) > 100 else ""),
    data={"team_id": str(team_id), "team_name": team_name, "type": "chat_message"}
  )

@app.route('/getMessages', methods=['GET'])
@token_required
def get_messages(current_user):
    """
    Get messages for a team
    ---
    tags:
      - Messages
    security:
      - Bearer: [] 
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
      400:
        description: Missing teamID
      401:
        description: User not authorized
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
@token_required
def get_project_tasks(current_user):
    """
    Get all tasks for a project
    ---
    tags:
      - Tasks
    security:
      - Bearer: [] 
    parameters:
      - name: projectID
        in: query
        type: integer
        required: true
        description: ID of the project
    responses:
      200:
        description: List of tasks
      400: 
        description: Missing projectID
      401:
        description: User not authorized
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
@permission_required
def remove_team_member(current_user):
    """
    Remove a user from a team
    ---
    tags:
      - Teams
    security:
      - Bearer: [] 
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
      401:
        description: User not authorized
      403:
        description: User does not have permission to remove members from this team
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
@permission_required
def create_task(current_user):
    """
    Create a task in a project
    ---
    tags:
      - Tasks
    security:
      - Bearer: [] 
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
      401:
        description: User not authorized
      403: 
        description: User does not have permission to create tasks in this project
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
    security:
      - Bearer: [] 
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
      401:
        description: User not authorized
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


@app.route('/device_token', methods=['PUT'])
@token_required
def update_device_token(current_user):
    """
    Update FCM device token status (activate/deactivate)
    ---
    tags:
      - Notifications
    security:
      - Bearer: [] 
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
      401:
        description: User not authorized
    """
    data = request.get_json()
    is_active = data.get('is_active')
    token = data.get('token')
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

def get_access_token():
    credentials = service_account.Credentials.from_service_account_file(
        SERVICE_ACCOUNT_FILE,
        scopes=["https://www.googleapis.com/auth/firebase.messaging"]
    )
    auth_req = google.auth.transport.requests.Request()
    credentials.refresh(auth_req)
    return credentials.token

def send_push_notifications(fcm_tokens, title, body, data=None,image_url=None):
  access_token = get_access_token()
  headers = {
    'Authorization': f'Bearer {access_token}',
    'Content-Type': 'application/json; UTF-8',
  }

  for token in fcm_tokens:
    team_name = data.get("team_name", "Unknown Team") if data else "Unknown Team"
   
    payload = {
      "message": {
        "token": token,
        "notification": {
          "title": title,
          "body": f"Team Name: {team_name}\n{body}",
          "image": image_url if image_url else None
        },
        "data": {k: str(v) for k, v in (data or {}).items()}
      }
    }

    response = requests.post(
      FCM_ENDPOINT,
      headers=headers,
      data=json.dumps(payload)
    )

    if response.status_code != 200:
      print(f"Failed to send message to {token}: {response.text}")
    else:
      print(f"Notification sent to {token}")

@app.route('/modifyTaskStatus', methods=['PUT'])
@token_required
@permission_required
def modify_task_status(current_user):
    """
    Modify the status of a task
    ---
    tags:
      - Tasks
    security:
      - Bearer: [] 
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - task_id
            - completed
          properties:
            task_id:
              type: integer
              example: 1
            completed:
              type: boolean
              example: true
    responses:
      200:
        description: Task status updated successfully
      400:
        description: Missing task_id or completed status
      404:
        description: Task not found
      401:
        description: User not authorized
      403:
        description: User does not have permission to modify this task
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
        server.send_message(msg)

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
    print(new_password, email, code)
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
@app.route('/modifyUserRole', methods=['PUT'])
@token_required
@permission_required
def modify_user_role(current_user):
    """
    Modify the role of a user in a team
    ---
    tags:
      - Teams
    security:
      - Bearer: [] 
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - user_id
            - team_id
            - new_role
          properties:
            user_id:
              type: integer
            team_id:
              type: integer
            new_role:
              type: string
              enum: [member, admin, owner]
    responses:
      200:
        description: User role updated successfully
      400:
        description: Missing user_id, team_id, or new_role
      404:
        description: User or team not found
      401:
        description: User not authorized
      403:
        description: User does not have permission to modify this role
    """
    data = request.get_json()
    user_id = data.get('user_id')
    team_id = data.get('team_id')
    new_role = data.get('new_role')

    if not user_id or not team_id or not new_role:
        return jsonify({"error": "Missing user_id, team_id, or new_role"}), 400

    if new_role not in ['member', 'admin', 'owner']:
        return jsonify({"error": "Invalid role"}), 400

    user_team = UserTeam.query.filter_by(user_id=user_id, team_id=team_id).first()

    if not user_team:
        return jsonify({"error": "User is not a member of the team"}), 404

    user_team.role = new_role
    db.session.commit()

    return jsonify({"message": "User role updated successfully"}), 200

@app.route('/updateProfilePicture', methods=['PUT'])
@token_required
def update_profile_picture(current_user):
    """
    Update the profile picture of a user
    ---
    tags:
      - Users
    security:
      - Bearer: [] 
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - userId
            - profilePicture
          properties:
            userId:
              type: integer
            profilePicture:
              type: string
              description: Base64 encoded image
    responses:
      200:
        description: Profile picture updated successfully
      400:
        description: Missing userId or profilePicture
      404:
        description: User not found
      401:
        description: User not authorized
    """
    data = request.get_json()
    user_id = data.get('userId')
    profile_picture = data.get('profilePicture')

    if not user_id or not profile_picture:
        return jsonify({"error": "Missing userId or profilePicture"}), 400

    user = User.query.filter_by(id=user_id).first()

    if not user:
        return jsonify({"error": "User not found"}), 404

    try:
        user.profile_picture = profile_picture.encode('utf-8')
        db.session.commit()
    except Exception as e:
        return jsonify({"error": f"Failed to update profile picture: {str(e)}"}), 500

    return jsonify({
        "message": "Profile picture updated successfully",
        "profile_picture": user.profile_picture.decode('utf-8') if user.profile_picture else None
    }), 200


@app.route('/modifyTaskAssignedTo', methods=['PUT'])
@token_required
@permission_required
def modify_task_assigned_to(current_user):
  """
  Modify the assigned user of a task
  ---
  tags:
    - Tasks
  security:
    - Bearer: [] 
  parameters:
    - in: body
    name: body
    required: true
    schema:
      type: object
      required:
      - task_id
      - assigned_to
      properties:
      task_id:
        type: integer
        description: ID of the task
      assigned_to:
        type: integer
        description: ID of the user to assign the task to
  responses:
    200:
    description: Task assignment updated successfully
    400:
    description: Missing task_id or assigned_to
    404:
    description: Task or user not found
    401:
    description: User not authorized
    403:
    description: User does not have permission to modify this task
  """
  data = request.get_json()
  task_id = data.get('task_id')
  assigned_to = data.get('assigned_to')

  if not task_id or not assigned_to:
    return jsonify({"error": "Missing task_id or assigned_to"}), 400

  task = Task.query.filter_by(id=task_id).first()
  if not task:
    return jsonify({"error": "Task not found"}), 404

  user = User.query.filter_by(id=assigned_to).first()
  if not user:
    return jsonify({"error": "User not found"}), 404

  task.assigned_to = assigned_to
  db.session.commit()

  return jsonify({"message": "Task assignment updated successfully"}), 200


@app.route('/getUserTasks', methods=['GET'])
@token_required
def get_user_tasks(current_user):
  """
  Get all tasks assigned to the user
  ---
  tags:
    - Tasks
  security:
    - Bearer: [] 
  parameters:
    - name: user_id
    in: query
    type: integer
    required: true
    description: ID of the user
  responses:
    200:
    description: List of tasks
    400:
    description: Missing user_id
    401:
    description: User not authorized
  """
  user_id = request.args.get('user_id', type=int)

  if user_id is None:
    return jsonify({"error": "user_id is required"}), 400

  tasks = db.session.query(Task, Project, Team)\
    .join(Project, Task.project_id == Project.id)\
    .join(Team, Project.team_id == Team.id)\
    .filter(Task.assigned_to == user_id).all()
  print(tasks)
  task_list = []
  for task, project, team in tasks:
    task_list.append({
      "team_name": team.name,
      "task_name": task.name,
      "task_description": task.description,
      "task_completed": task.completed,
      "deadline": task.deadline.isoformat() if task.deadline else None
    })

  return jsonify(task_list), 200

@app.route('/getUserInfo', methods=['GET'])
@token_required
def get_user_info(current_user):
    """
    Get information about a specific user
    ---
    tags:
      - Users
    security:
      - Bearer: []
    parameters:
      - name: user_id
        in: query
        type: integer
        required: true
        description: ID of the user
    responses:
      200:
        description: User information
      400:
        description: Missing user_id
      404:
        description: User not found
      401:
        description: Unauthorized
    """
    user_id = request.args.get('user_id', type=int)

    if user_id is None:
        return jsonify({"error": "user_id is required"}), 400

    user = User.query.filter_by(id=user_id).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    user_info = {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "profile_picture": user.profile_picture.decode('utf-8') if user.profile_picture else None
    }

    return jsonify(user_info), 200


if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
