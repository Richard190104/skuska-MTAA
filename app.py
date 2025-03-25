from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash



app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:Bhmk7gh90r@localhost:5432/MTAAskuska'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)



class UserTeams(db.Model):
    __tablename__ = 'UserTeam'
    team_id = db.Column('teamID', db.Integer, db.ForeignKey('Teams.id'), primary_key=True)
    user_id = db.Column('userID', db.Integer, db.ForeignKey('Users.id'), primary_key=True)
    role = db.Column(db.String(50))



class Teams(db.Model):
    __tablename__ = 'teams'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    creator = db.Column(db.String(100), nullable=True)


class users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)  

    def set_password(self, password):
        self.password_hash = generate_password_hash(password) 

    def check_password(self, password):
        return check_password_hash(self.password_hash, password) 


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    print(data)
    new_user = users(username=data['username'], email=data['email'])
    new_user.set_password(data['password'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User registered successfully!"}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = users.query.filter_by(email=data['email']).first()

    if user and user.check_password(data['password']):  
        return jsonify({"message": "Login successful!", "userID": user.id}), 200
    else:
         jsonify({"error": "Invalid email or password"}), 401

from flask import request

@app.route('/getTeams', methods=['GET'])
def get_teams():
    user_id = request.args.get('userID', type=int)
    
    if user_id is None:
        return jsonify({"error": "userID is required"}), 400

    results = db.session.query(Teams).join(UserTeams, Teams.id == UserTeams.team_id)\
        .filter(UserTeams.user_id == user_id).all()
    print(results)
    teams = []
    for team in results:
        teams.append({
            "id": team.id,
            "name": team.name,
            "creator": team.creator
        })
    print(teams)
    return jsonify(teams), 200




if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)


