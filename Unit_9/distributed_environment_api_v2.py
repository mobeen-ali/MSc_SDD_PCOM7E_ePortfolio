
from flask import Flask, jsonify
from flask_restful import Api, Resource, reqparse

app = Flask(__name__)
api = Api(app)

users = [
    {"name": "James", "age": 30, "occupation": "Network Engineer"},
    {"name": "Ann", "age": 32, "occupation": "Doctor"},
    {"name": "Jason", "age": 22, "occupation": "Web Developer"}
]

parser = reqparse.RequestParser()
parser.add_argument("age", type=int, required=True, help="Age must be an integer")
parser.add_argument("occupation", type=str, required=True, help="Occupation cannot be blank")

class User(Resource):
    def get(self, name):
        for user in users:
            if user["name"].lower() == name.lower():
                return jsonify(user)
        return {"message": "User not found"}, 404

    def post(self, name):
        args = parser.parse_args()
        if any(user["name"].lower() == name.lower() for user in users):
            return {"message": f"User with name '{name}' already exists"}, 400

        user = {"name": name, "age": args["age"], "occupation": args["occupation"]}
        users.append(user)
        return user, 201

    def put(self, name):
        args = parser.parse_args()
        for user in users:
            if user["name"].lower() == name.lower():
                user.update({"age": args["age"], "occupation": args["occupation"]})
                return user, 200

        user = {"name": name, "age": args["age"], "occupation": args["occupation"]}
        users.append(user)
        return user, 201

    def delete(self, name):
        global users
        users = [user for user in users if user["name"].lower() != name.lower()]
        return {"message": f"User '{name}' deleted."}, 200

api.add_resource(User, "/user/<string:name>")

if __name__ == "__main__":
    app.run(debug=True)
