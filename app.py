import json
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta
from flask import Flask,jsonify,request,redirect, url_for
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from sqlalchemy.orm import backref
import jwt
import pytz
from chat import create_timestamps_youtube_video

load_dotenv()

app = Flask(__name__)
CORS(app)

#For deployment
DATABASE_URI = f'mysql+mysqlconnector://smartbookmark-user:{os.environ.get("GCP_DB_PASSWORD")}@{os.environ.get("GCP_DB_PRIVATE_IP")}:3306/smartbookmark'

# DATABASE_URI = f'mysql+mysqlconnector://Ugyen:password@localhost/smart_bookmark_db'
#For Local Machine

#SQL ALCHEMY config
app.config['SECRET_KEY'] = "adhfuixhnecaycdunalfdshakjch"
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# User Table
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(30), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    bookmarks = db.relationship('Video')

    def __init__(self, email, name, password):
        self.email = email
        self.name = name
        self.password = password

# Video Table
class Video(db.Model):
    __tablename__ = 'videos'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    url = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    last_viewed=db.Column(db.DateTime, default=datetime.now)
    bookmarks = db.relationship('Bookmark',cascade="all, delete", backref='video')

    def __init__(self, user_id, url):
        self.user_id=user_id
        self.url = url

    def last_viewed_ist(self):
        gmt = pytz.timezone('GMT')
        ist = pytz.timezone('Asia/Kolkata')
        gmt_time = self.last_viewed.replace(tzinfo=gmt)
        ist_time = gmt_time.astimezone(ist)
        return ist_time

# Bookmark Table
class Bookmark(db.Model):
    __tablename__ = 'bookmarks'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    notes = db.Column(db.String(300))
    created_at = db.Column(db.DateTime, default=datetime.now)
    video_id = db.Column(db.Integer, db.ForeignKey('videos.id'))
    timestamp = db.Column(db.String(20), nullable=False)
    is_shared = db.Column(db.Boolean, default=False, nullable=False)
 
    def __init__(self, notes, video_id, timestamp, is_shared):
        self.notes = notes
        self.video_id = video_id
        self.timestamp = timestamp
        self.is_shared = is_shared

# Timestamp   
class Timestamp(db.Model):
    __tablename__ = 'timestamps'
    id=db.Column(db.Integer, primary_key=True, autoincrement=True)
    url = db.Column(db.String(60),primary_key=True)
    notes = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.String(100), nullable=False)
    def __init__(self, url, notes, timestamp):
        self.url = url
        self.notes = notes
        self.timestamp = timestamp

# Creating the Tables in the database
with app.app_context():
    db.create_all()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message': 'Token is missing','status':401,'isSuccess':0}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'],'HS256')
            current_user = User.query.filter_by(email=data['email']).first()
        except Exception as e:
            print(e)
            return jsonify({'message': 'Token is invalid','status':401,'isSuccess':0}), 401
        return f(current_user, *args, **kwargs)
    return decorated

@app.route("/")
def getHello():
    return "Hello world!"

# User signup Routes
@app.route("/signup", methods=["POST"])
def signUpUser():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    name = data.get("name")

    if not email or not password or not name:
        return jsonify({'message': 'Email, Password and Name  are required.','status':400,'isSuccess':0}), 400
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({'message': 'Email already exists','status':409,'isSuccess':0}), 409
    try:
        new_user = User(email=email, password=generate_password_hash(password, method='sha256'), name= name)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User created successfully.','status':201,'Name':name,'isSuccess':1}), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'message': str(e),'status':500,'isSuccess':0}), 500

# User signin Routes
@app.route('/signin', methods=['POST'])
def sign_in():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return jsonify({'message':'Could not verify','status':401,'isSuccess':0}), 401
    user = User.query.filter_by(email=auth.username).first()
    if not user:
        return jsonify({'message':'Could not verify','status':401,'isSuccess':0}), 401

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'email': auth.username, 'exp':datetime.utcnow()+timedelta(hours=6)}, app.config['SECRET_KEY'])
        return jsonify({'token': token,'status':200,'isSuccess':1})

    return jsonify({'message':'Could not verify','status':401,'isSuccess':0}), 401

@app.route("/user", methods=["GET"])
@token_required
def get_user(current_user):
    try:
        results = User.query.filter_by(id=current_user.id).all()
        if not results:
            return jsonify({'message': "This user does not exist in the database",'status':400,'isSuccess':0})
        user_list = []
        for user in results:
            user_data = {
                'name': user.name,
                'email': user.email
            }
            user_list.append(user_data)
        return jsonify({'user_details':user_list,'status':200,'isSuccess':1}), 200

    except Exception as e:
        return jsonify({'message': str(e),'status':500,'isSuccess':0}), 500

# Add videos
@app.route("/videos", methods=["POST"])
@token_required
def add_video(current_user):
    data = request.get_json()
    url = data.get("url")

    if not url:
        return jsonify({'message': "Video Url can not be Empty",'status':400,"isSuccess":0}),400

    video = Video.query.filter_by(user_id = current_user.id).filter_by(url = url).first()
    if video:
        return jsonify({'message': "Video Url already exist in the database", 'status':200, "video_id":video.id,"isSuccess":0}), 200
    try:
        new_video = Video(url=url, user_id=current_user.id)
        db.session.add(new_video)
        db.session.commit()
        return jsonify({'message': 'Video added successfully.' ,'status':201, "video_id":new_video.id,"isSuccess":1}), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'message': str(e),'status':500,"isSuccess":0}), 500

# Fetch not shared videos by user_id
@app.route("/videos", methods=["GET"])
@token_required
def get_video(current_user):
    try:
        results = Video.query.filter_by(user_id=current_user.id).all()
        video_list = []
        for video in results:
            is_shared_vidoe = Bookmark.query.filter_by(video_id=video.id).filter_by(is_shared=False).all()
            if len(is_shared_vidoe) >= 1:
                video_data = {
                    'id': video.id,
                    'url': video.url,
                    'user_id': video.user_id,
                    "last_viewed": video.last_viewed
                }
                video_list.append(video_data)
        return jsonify({"video_details":video_list,"status":200,"isSuccess":1}), 200

    except Exception as e:
        return jsonify({'message': str(e),'status':500,"isSuccess":0}), 500
    
# Fetch shared videos by user_id
@app.route("/sharedvideos", methods=["GET"])
@token_required
def get_shared_video(current_user):
    try:
        results = Video.query.filter_by(user_id=current_user.id).all()
        video_list = []
        for video in results:
            print("Id: ", video.id)
            is_shared_vidoe = Bookmark.query.filter_by(video_id=video.id).filter_by(is_shared=True).all()
            if len(is_shared_vidoe) >= 1:
                video_data = {
                    'id': video.id,
                    'url': video.url,
                    'user_id': video.user_id,
                    "last_viewed": video.last_viewed
                }
                video_list.append(video_data)
        return jsonify({"video_details":video_list,"status":200,"isSuccess":1}), 200

    except Exception as e:
        return jsonify({'message': str(e),'status':500,"isSuccess":0}), 500

# Delete videos by video_id
@app.route("/videos/<video_id>/<is_shared>", methods=["DELETE"])
@token_required
def delete_video(current_user,video_id, is_shared):
        results = Video.query.filter_by(user_id=current_user.id,id=video_id).first()
        if not results:
            return jsonify({'message': 'Video does not exist','status':404,'isSuccess':0}), 404
        try:
            if is_shared == 'true':
                bookmarks = Bookmark.query.filter_by(video_id=video_id).filter_by(is_shared=True).all()
                for bookmark in bookmarks:
                    db.session.delete(bookmark)
                    db.session.commit()
                return jsonify({'message': 'Video deleted successfully.','status':200,'isSuccess':1}), 200
            else:
                bookmarks = Bookmark.query.filter_by(video_id=video_id).filter_by(is_shared=False).all()
                for bookmark in bookmarks:
                    db.session.delete(bookmark)
                    db.session.commit()
                return jsonify({'message': 'Video deleted successfully.','status':200,'isSuccess':1}), 200
            
        except Exception as e:
            return jsonify({'message': str(e),'status':500,"isSuccess":0}), 500

# Update last watched
@app.route("/lastvideos/<video_id>", methods=["GET"])
@token_required
def get_video_byid(current_user,video_id):
    try:
        result = Video.query.filter_by(user_id=current_user.id).filter_by(id=video_id).first()
        if not result:
            return jsonify({'message': "Video Url does not exist in the database",'status':400,"isSuccess":0})
        result.last_viewed = datetime.now
        db.session.commit()
        return jsonify({'message': 'Last viewed updated successfully.','status':200, "video_watched_at":result.last_viewed,"isSuccess":1}), 200

    except Exception as e:
        return jsonify({'message': str(e),'status':500,"isSuccess":0}), 500

    
@app.route("/lastvideos", methods=["GET"])
@token_required
def get_last_videos(current_user):
    try:
        results = Video.query.filter_by(user_id=current_user.id).order_by(Video.last_viewed.desc()).limit(5).all()
        video_list = []
        for video in results:
            video_data = {
                'id': video.id,
                'url': video.url,
                'user_id': video.user_id,
                "last_viewed": video.last_viewed
            }
            video_list.append(video_data)
        return jsonify({"video_details":video_list,"status":200,"isSuccess":1}),200

    except Exception as e:
        return jsonify({'message': str(e),"status":500,"isSuccess":0,}), 500

# Add bookmarks
@app.route("/bookmark", methods=["POST"])
@token_required
def add_bookmark(current_user):
    data = request.get_json()
    notes = data.get("notes")
    video_id = data.get("video_id")
    timestamp = data.get("timestamp")
    is_shared = data.get("is_shared")

    video = Video.query.filter_by(user_id = current_user.id).filter_by(id=video_id).all()
    if not video:
        return jsonify({'message': "Video Url does not exist in the database",'status':400,'isSuccess':0}),400

    try:
        if is_shared == True:
            isTimestampPresent = Bookmark.query.filter_by(video_id=video_id).filter_by(is_shared= True).filter_by(timestamp = timestamp).all()
            if not isTimestampPresent:
                new_bookmark = Bookmark(notes=notes, video_id=video_id, timestamp=timestamp, is_shared=True)
                db.session.add(new_bookmark)
                db.session.commit()
                return jsonify({'message': 'Bookmark added successfully.','status':201,'video_id':video_id,'isSuccess':1}), 201
        else:
            isTimestampPresent = Bookmark.query.filter_by(video_id=video_id).filter_by(is_shared= False).filter_by(timestamp = timestamp).all()
            if not isTimestampPresent:
                new_bookmark = Bookmark(notes=notes, video_id=video_id, timestamp=timestamp, is_shared=False)
                db.session.add(new_bookmark)
                db.session.commit()
                
                result = Video.query.filter_by(user_id=current_user.id).filter_by(id=video_id).first()
                result.last_viewed = datetime.now()
                db.session.commit()
                return jsonify({'message': 'Bookmark added successfully.','status':201,'video_id':video_id,'isSuccess':1}), 201

        return jsonify({'message': 'Bookmark at this timestamp already exist','status':201,'video_id':video_id,'isSuccess':1}), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': str(e),'status':500,'isSuccess':0}), 500

 
@app.route("/bookmark/<int:video_id>", methods=["GET"])
@token_required
def get_bookmark(current_user, video_id):
    if not video_id:
        return jsonify({'message': "Video ID cannot be Empty",'status':400,'isSuccess':0}), 400

    user = User.query.filter_by(id=current_user.id).first()
    video = Video.query.filter_by(user_id = current_user.id).filter_by(id=video_id).first()
    if not video:
        return jsonify({'message': "Video Url does not exist in the database",'status':400,'isSuccess':0}),400
    try:
        results = Bookmark.query.filter_by(video_id=video_id).filter_by(is_shared = False).all()
        bookmark_list = []
        for bookmark in results:
            bookmark_data = {
                'id': bookmark.id,
                'notes': bookmark.notes,
                'timestamp': bookmark.timestamp,
                'created_at':bookmark.created_at,
                'is_shared' : bookmark.is_shared
            }
            bookmark_list.append(bookmark_data)
        return jsonify({"bookmark_details":bookmark_list,"status":200,"isSuccess":1}), 200

    except Exception as e:
        return jsonify({'message': str(e),'status':500,'isSuccess':0}), 500
    
@app.route("/sharedbookmark/<int:video_id>", methods=["GET"])
@token_required
def get_shared_bookmark(current_user, video_id):
    if not video_id:
        return jsonify({'message': "Video ID cannot be Empty",'status':400,'isSuccess':0}), 400
    video = Video.query.filter_by(user_id = current_user.id).filter_by(id=video_id).first()
    if not video:
        return jsonify({'message': "Video Url does not exist in the database",'status':400,'isSuccess':0}),400
    try:
        results = Bookmark.query.filter_by(video_id=video_id).filter_by(is_shared = True).all()
        bookmark_list = []
        for bookmark in results:
            bookmark_data = {
                'id': bookmark.id,
                'notes': bookmark.notes,
                'timestamp': bookmark.timestamp,
                'created_at':bookmark.created_at,
                'is_shared' : bookmark.is_shared
            }
            bookmark_list.append(bookmark_data)
        return jsonify({"bookmark_details":bookmark_list,"status":200,"isSuccess":1}), 200

    except Exception as e:
        return jsonify({'message': str(e),'status':500,'isSuccess':0}), 500

@app.route("/bookmark/<int:bookmark_id>", methods=["PUT"])
@token_required
def edit_bookmark_notes(current_user, bookmark_id):
    data = request.get_json()
    notes = data.get("notes")

    if not notes:
        return jsonify({'message': "New notes cannot be empty",'status':400,'isSuccess':0}), 400

    bookmark = Bookmark.query.filter_by(id=bookmark_id).first()
    video = Video.query.filter_by(id=bookmark.video_id, user_id=current_user.id).first()
    if not video:
        return jsonify({'message': 'Unauthorized','status':401,'isSuccess':0}), 401

    if not bookmark:
        return jsonify({'message': "Bookmark does not exist for this video",'status':404,'isSuccess':0}), 404

    try:
        bookmark.notes = notes
        db.session.commit()
        return jsonify({'message': 'Bookmark notes updated successfully.','status':200,'updated_note':bookmark.notes,'video_id':video.id,'isSuccess':1}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'message': str(e),'status':500,'isSuccess':0}), 500

@app.route("/bookmark/<int:bookmark_id>", methods=["DELETE"])
@token_required
def delete_bookmark(current_user,bookmark_id):
    bookmark = Bookmark.query.filter_by(id=bookmark_id).first()
    if not bookmark:
        return jsonify({'message': 'Bookmark does not exist','status':400,'isSuccess':0}), 404     

    video = Video.query.filter_by(user_id=current_user.id, id=bookmark.video_id).first()
    if not video:
        return jsonify({'message': "Video URL does not exist in the database",'status':404,'isSuccess':0}), 404

    try:
        db.session.delete(bookmark)
        db.session.commit()
        return jsonify({'message': 'Bookmark deleted successfully.','status':200,'isSuccess':1,'video_id':video.id}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'message': str(e),'status':500,'isSuccess':0}), 500

    
@app.route("/videos/<int:video_id>", methods=["GET"])
@token_required
def get_video_details_with_bookmarks(current_user, video_id):
    if not current_user.id:
        return jsonify({'message': 'Unauthorized', 'status': 401, 'isSuccess': 0}), 401

    # Get the video and its bookmarks if it belongs to the current user
    video = Video.query.filter_by(id=video_id).first()
    if not video:
        return jsonify({'message': "Video URL does not exist in the database", 'status': 404, 'isSuccess': 0}), 404
    try:
        video_data = {
            'id': video.id,
            'url': video.url,
            'user_id': video.user_id,
            'bookmarks': []
        }

        # Retrieve all bookmarks associated with the video
        bookmarks = Bookmark.query.filter_by(video_id=video_id).all()
        for bookmark in bookmarks:
            bookmark_data = {
                'id': bookmark.id,
                'notes': bookmark.notes,
                'timestamp': bookmark.timestamp,
                'created_at': bookmark.created_at
            }
            video_data['bookmarks'].append(bookmark_data)

        return jsonify({'video_details': video_data, 'status': 200, 'isSuccess': 1}), 200

    except Exception as e:
        return jsonify({'message': str(e), 'status': 500, 'isSuccess': 0}), 500


@app.route('/bookmarkshare/<int:video_id>')
def share_bookmarks(video_id):
    share_url = f"https://smartbookmark-frontend-urtjok3rza-wl.a.run.app/share/{video_id}"
    return redirect(share_url)


@app.route('/aitimestamp', methods=["POST"])
def ai_timestamp():
    data = request.get_json()
    url = data.get('url')
    try:
        results = Timestamp.query.filter_by(url=url).all()
        print("THe video already exist!!: ", results)
        if not results:
            api_result = create_timestamps_youtube_video(url)
            print("THis is api end: ", api_result)
            if api_result is None:
                return jsonify({'timestamp_details':[],'status':200,'isSuccess':0,'message': f"Transcript can't be generated for the particular youtube video: {url}"}), 200
            new_result = json.loads(api_result)
            for res in new_result:  
                result = Timestamp.query.filter_by(url=url).filter_by(timestamp=res['timestamp']).first()
                if not result:
                    new_timestamp = Timestamp(url=url, timestamp=res['timestamp'], notes=res['notes'])
                    db.session.add(new_timestamp)
                    db.session.commit()
                
            results = Timestamp.query.filter_by(url=url).all()

            timestamp_list = []
            for timestamp in results:
                timestamp_detail = {
                    'timestamp': timestamp.timestamp,
                    'note': timestamp.notes,
                    'url':timestamp.url
                }
                timestamp_list.append(timestamp_detail)
            return jsonify({'timestamp_details':timestamp_list,'status':200,'isSuccess':1}), 200

        timestamp_list = []
        for timestamp in results:
            timestamp_detail = {
                    'timestamp': timestamp.timestamp,
                    'note': timestamp.notes,
                    'url':timestamp.url
                }
            timestamp_list.append(timestamp_detail)
        return jsonify({'timestamp_details':timestamp_list,'status':200,'isSuccess':1}), 200
    except Exception as e:
        return jsonify({'message': str(e),'status':500,'isSuccess':0}), 500

    
if __name__ == "__main__":
    app.run(debug=False)