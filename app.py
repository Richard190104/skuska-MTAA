from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:Bhmk7gh90r@localhost:5432/MTAAskuska'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ✅ user_teams – FK správne viazané na integer ID
class UserTeam(db.Model):
    __tablename__ = 'user_teams'
    team_id = db.Column(db.Integer, db.ForeignKey('teams.id'), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    role = db.Column(db.String(50))

# ✅ teams – creator_id ako integer FK
class Team(db.Model):
    __tablename__ = 'teams'
    id = db.Column(db.Integer, primary_key=True )
    name = db.Column(db.String(100), nullable=False)
    creator_id = db.Column(db.Integer, db.ForeignKey('users.id'))

# ✅ users – všetko integer ID
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
        return jsonify({"message": "Login successful!", "userID": user.id}), 200
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
            "team_id": project.team_id
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


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
