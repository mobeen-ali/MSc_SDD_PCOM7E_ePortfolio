from flask import Flask
from flask_restful import Api, Resource, reqparse

app = Flask(__name__)
api = Api(app)

users = [
    {"name": "James", "age": 30, "occupation": "Network Engineer"},
    {"name": "Ann", "age": 32, "occupation": "Doctor"},
    {"name": "Jason", "age": 22, "occupation": "Web Developer"}
]

class User(Resource):
    def get(self, name):
        for user in users:
            if user["name"] == name:
                return user, 200
        return "User not found", 404

    def post(self, name):
        parser = reqparse.RequestParser()
        parser.add_argument("age")
        parser.add_argument("occupation")
        args = parser.parse_args()

        for user in users:
            if user["name"] == name:
                return f"User with name {name} already exists", 400

        user = {
            "name": name,
            "age": args["age"],
            "occupation": args["occupation"]
        }
        users.append(user)
        return user, 201

    def put(self, name):
        parser = reqparse.RequestParser()
        parser.add_argument("age")
        parser.add_argument("occupation")
        args = parser.parse_args()

        for user in users:
            if user["name"] == name:
                user["age"] = args["age"]
                user["occupation"] = args["occupation"]
                return user, 200

        user = {
            "name": name,
            "age": args["age"],
            "occupation": args["occupation"]
        }
        users.append(user)
        return user, 201

    def delete(self, name):
        global users
        users = [user for user in users if user["name"] != name]
        return f"{name} is deleted.", 200

api.add_resource(User, "/user/<string:name>")

if __name__ == "__main__":
    app.run(debug=True)
