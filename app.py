import re

from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from geoalchemy2.functions import ST_AsText
from shapely import get_coordinates
from flask import request, jsonify
import pandas as pd
from geoalchemy2 import Geometry
from geoalchemy2.shape import to_shape
from flask_jwt_extended import jwt_required, create_access_token, get_jwt_identity
import json

from sqlalchemy import func, text

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "http://localhost:3000"}})
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:Qwerty123456@localhost/winery_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your-secret-key'  # Change this to a secure secret key
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)


class Rating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    winery_id = db.Column(db.Integer, db.ForeignKey('winery.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    user = db.relationship('User', backref=db.backref('ratings', lazy=True))
    winery = db.relationship('Winery', backref=db.backref('ratings', lazy=True))


from geoalchemy2.functions import ST_X, ST_Y

class Winery(db.Model):
    __tablename__ = 'winery'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    location = db.Column(Geometry(geometry_type='POINT', srid=4326))
    average_rating = db.Column(db.Float, default=0.0)

    @property
    def region(self):
        return get_region(self.latitude, self.longitude)

    @property
    def latitude(self):
        return db.session.scalar(func.ST_Y(self.location))

    @property
    def longitude(self):
        return db.session.scalar(func.ST_X(self.location))

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'latitude': self.latitude,
            'longitude': self.longitude,
            'average_rating': self.average_rating,
            'region': self.region
        }

def load_geojson(file_path):
    with open(file_path) as file:
        data = json.load(file)
    return data


def insert_wineries(geojson_data):
    for feature in geojson_data['features']:
        name = feature['properties'].get('Name')
        description = feature['properties'].get('description')
        longitude, latitude = feature['geometry']['coordinates']
        location = f'POINT({longitude} {latitude})'

        def clean_description(description):
            # Remove <br> tags
            clean_desc = re.sub(r'<br>', ' ', description)
            # Remove "myyain" references
            clean_desc = re.sub(r'\bmyyain\b', '', clean_desc, flags=re.IGNORECASE)
            return clean_desc.strip()

        def extract_location(description):
            # Example of extracting location from the description
            # Adjust the regex pattern based on the actual format of the location data in the description
            match = re.search(r'GPS: \s*(\d+\.\d+,\s*\d+\.\d+)', description, re.IGNORECASE)
            if match:
                data = match.group(1)
                data = [float(num.replace(',', '')) for num in data.split()]
                location = f'POINT({data[1]} {data[0]})'
                return location
            return None

        description = clean_description(description)
        if not location or location == 'POINT(0.0 0.0)':
            location = extract_location(description)

        winery = Winery(name=name, description=description, location=location)
        db.session.add(winery)
    db.session.commit()


@app.route('/wineries/<int:winery_id>/rate', methods=['POST'])
@jwt_required()
def rate_winery(winery_id):
    current_user = get_jwt_identity()
    data = request.json
    rating_value = data['rating']

    # Find the winery
    winery = Winery.query.get_or_404(winery_id)
    # Check if user already rated this winery
    user = User.query.filter_by(username=current_user['username']).first()

    existing_rating = Rating.query.filter_by(user_id=user.id, winery_id=winery_id).first()
    if existing_rating:
        existing_rating.rating = rating_value
    else:
        new_rating = Rating(winery_id=winery_id, user_id=user.id, rating=rating_value)
        db.session.add(new_rating)

    # Calculate the new average rating
    all_ratings = Rating.query.filter_by(winery_id=winery_id).all()
    average_rating = sum(r.rating for r in all_ratings) / len(all_ratings)
    winery.average_rating = average_rating

    db.session.commit()

    return jsonify(winery.to_dict()), 200


@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    is_admin = data.get('is_admin', False)

    if User.query.filter_by(username=username).first():
        return jsonify({"msg": "Username already exists"}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, password=hashed_password, is_admin=is_admin)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"msg": "User created successfully", "is_admin": is_admin}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    if user and bcrypt.check_password_hash(user.password, password):
        access_token = create_access_token(identity={'username': username, 'is_admin': user.is_admin})
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"msg": "Invalid username or password"}), 401


@app.route('/wineries', methods=['GET'])
@jwt_required()
def get_wineries():
    # def drop_table(table_name):
    #     with app.app_context():
    #         # Reflect the existing database into a new metadata object
    #         meta = db.MetaData()
    #         meta.reflect(bind=db.engine)
    #
    #         # Check if the table exists before trying to drop it
    #         if table_name in meta.tables:
    #             table = meta.tables[table_name]
    #             table.drop(bind=db.engine)
    #         else:
    #             print(f"Table '{table_name}' does not exist in the database.")
    # drop_table('rating')
    # drop_table('winery')
    # with app.app_context():
    #     db.create_all()
    # insert_wineries(load_geojson('wineries.geojson'))
    # subquery = db.session.query(
    #     Winery.name,
    #     func.min(Winery.id).label('min_id')
    # ).group_by(Winery.name).subquery()
    #
    # # Query to select all wineries that are duplicates (not the ones with minimum ID)
    # duplicates = Winery.query.filter(
    #     ~Winery.id.in_(db.session.query(subquery.c.min_id))
    # ).all()
    #
    # # Delete the duplicates
    # for duplicate in duplicates:
    #     db.session.delete(duplicate)
    #
    # # Function to update the data in the PostgreSQL database
    # def update_data():
    #     all_wineries = Winery.query.all()
    #     for winery_ in all_wineries:
    #         # Clean the description
    #         cleaned_description = clean_description(winery_.description)
    #
    #         # Extract location if missing
    #         if pd.isna(winery_.location) or winery_.location.desc == '0101000020E610000000000000000000000000000000000000'.lower():
    #             extracted_location = extract_location(winery_.description)
    #             if extracted_location:
    #                 winery_.location = extracted_location
    #
    #             update_query = text("""
    #             UPDATE wineries
    #             SET name = %s,
    #                 description = %s,
    #                 location = %s,
    #                 average_rating = %s
    #             WHERE id = %s
    #             """)
    #             db.session.execute(update_query, (
    #                 winery_.name,
    #                 cleaned_description,
    #                 winery_.location,
    #                 winery_.average_rating,
    #                 winery_.id
    #             ))
    #             db.session.commit()
    # #update_data()
    db.session.commit()

    wineries = Winery.query.all()
    return jsonify([winery.to_dict() for winery in wineries])


@app.route('/wineries', methods=['POST'])
@jwt_required()
def add_winery():
    current_user = get_jwt_identity()
    if not current_user['is_admin']:
        return jsonify({"msg": "Admin access required"}), 403

    data = request.json
    new_winery = Winery(
        name=data['name'],
        description=data['description'],
        location=f"POINT({data['longitude']} {data['latitude']})"
    )
    db.session.add(new_winery)
    db.session.commit()
    return jsonify(new_winery.to_dict()), 201


from flask import request

from shapely.geometry import Point, Polygon

ISRAEL_REGIONS = {
    "Galilee": {
        "type": "Polygon",
        "coordinates": [
            [[35.1, 32.7], [35.6, 32.7], [35.6, 33.3], [35.1, 33.3], [35.1, 32.7]]
        ]
    },
    "Golan Heights": {
        "type": "Polygon",
        "coordinates": [
            [[35.6, 32.7], [35.9, 32.7], [35.9, 33.3], [35.6, 33.3], [35.6, 32.7]]
        ]
    },
    "Upper Galilee": {
        "type": "Polygon",
        "coordinates": [
            [[35.2, 33.0], [35.6, 33.0], [35.6, 33.3], [35.2, 33.3], [35.2, 33.0]]
        ]
    },
    "Lower Galilee": {
        "type": "Polygon",
        "coordinates": [
            [[35.2, 32.7], [35.6, 32.7], [35.6, 33.0], [35.2, 33.0], [35.2, 32.7]]
        ]
    },
    "Judean Hills": {
        "type": "Polygon",
        "coordinates": [
            [[34.8, 31.3], [35.3, 31.3], [35.3, 32.0], [34.8, 32.0], [34.8, 31.3]]
        ]
    },
    "Samson": {
        "type": "Polygon",
        "coordinates": [
            [[34.6, 31.5], [34.9, 31.5], [34.9, 32.0], [34.6, 32.0], [34.6, 31.5]]
        ]
    },
    "Negev": {
        "type": "Polygon",
        "coordinates": [
            [[34.3, 30.0], [35.3, 30.0], [35.3, 31.3], [34.3, 31.3], [34.3, 30.0]]
        ]
    },
    "Sharon": {
        "type": "Polygon",
        "coordinates": [
            [[34.8, 32.0], [35.1, 32.0], [35.1, 32.5], [34.8, 32.5], [34.8, 32.0]]
        ]
    },
    "Shomron": {
        "type": "Polygon",
        "coordinates": [
            [[35.0, 32.0], [35.3, 32.0], [35.3, 32.5], [35.0, 32.5], [35.0, 32.0]]
        ]
    },
    "Carmel": {
        "type": "Polygon",
        "coordinates": [
            [[34.9, 32.5], [35.2, 32.5], [35.2, 32.8], [34.9, 32.8], [34.9, 32.5]]
        ]
    },
    "Shimshon": {
        "type": "Polygon",
        "coordinates": [
            [[34.7, 31.7], [35.0, 31.7], [35.0, 32.0], [34.7, 32.0], [34.7, 31.7]]
        ]
    },
    "Judean Foothills": {
        "type": "Polygon",
        "coordinates": [
            [[34.8, 31.5], [35.1, 31.5], [35.1, 31.8], [34.8, 31.8], [34.8, 31.5]]
        ]
    },
    "Jerusalem Mountains": {
        "type": "Polygon",
        "coordinates": [
            [[35.0, 31.6], [35.3, 31.6], [35.3, 31.9], [35.0, 31.9], [35.0, 31.6]]
        ]
    }
}

def get_region(lat, lon):
    point = Point(lon, lat)
    for region, geojson in ISRAEL_REGIONS.items():
        polygon = Polygon(geojson['coordinates'][0])
        if polygon.contains(point):
            return region
    return "Unknown"


@app.route('/wineries/search', methods=['GET'])
def search_wineries():
    name = request.args.get('name', '')
    min_rating = float(request.args.get('min_rating', 0))
    regions = request.args.get('regions', '').split(',')

    query = Winery.query

    if name:
        query = query.filter(Winery.name.ilike(f'%{name}%'))

    if min_rating > 0:
        query = query.filter(Winery.average_rating >= min_rating)

    wineries = query.all()

    # Filter by region
    if regions and regions != ['']:
        wineries = [w for w in wineries if get_region(w.latitude, w.longitude) in regions]

    return jsonify([winery.to_dict() for winery in wineries])


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
