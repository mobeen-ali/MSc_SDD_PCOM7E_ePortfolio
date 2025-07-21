"""
Distributed Environment REST API (v2)
-------------------------------------
A Flask-based secure RESTful API for managing user data in-memory.
Demonstrates principles of secure development, modular design, and clear API feedback.

"""

from flask import Flask, jsonify
from flask_restful import Api, Resource, reqparse
from werkzeug.exceptions import BadRequest

# Initialize the Flask application
app = Flask(__name__)
api = Api(app)

# In-memory user data (for demo only — no persistence)
users = [
    {"name": "James", "age": 30, "occupation": "Network Engineer"},
    {"name": "Ann", "age": 32, "occupation": "Doctor"},
    {"name": "Jason", "age": 22, "occupation": "Web Developer"}
]

# Define expected input arguments for POST and PUT requests
parser = reqparse.RequestParser()
parser.add_argument("age", type=int, required=True, help="Age must be an integer.")
parser.add_argument("occupation", type=str, required=True, help="Occupation cannot be blank.")


class User(Resource):
    """
    Handles CRUD operations for a single user identified by 'name'.
    """

    def get(self, name):
        """
        GET /user/<name>
        Retrieves a user's details by name (case-insensitive).
        """
        for user in users:
            if user["name"].lower() == name.lower():
                return jsonify(user)
        return {"message": f"User '{name}' not found."}, 404

    def post(self, name):
        """
        POST /user/<name>
        Creates a new user. Fails if user already exists.
        """
        args = parser.parse_args()

        # Check for duplicates
        if any(user["name"].lower() == name.lower() for user in users):
            return {"message": f"User with name '{name}' already exists."}, 400

        new_user = {"name": name, "age": args["age"], "occupation": args["occupation"]}
        users.append(new_user)
        return new_user, 201

    def put(self, name):
        """
        PUT /user/<name>
        Updates an existing user's details or creates one if not found.
        """
        args = parser.parse_args()

        for user in users:
            if user["name"].lower() == name.lower():
                user.update({"age": args["age"], "occupation": args["occupation"]})
                return user, 200

        new_user = {"name": name, "age": args["age"], "occupation": args["occupation"]}
        users.append(new_user)
        return new_user, 201

    def delete(self, name):
        """
        DELETE /user/<name>
        Deletes a user by name.
        """
        global users
        users = [user for user in users if user["name"].lower() != name.lower()]
        return {"message": f"User '{name}' deleted."}, 200


# Register User resource route
api.add_resource(User, "/user/<string:name>")

# Exportable accessor for external modules (test suite)
def get_users():
    return users

# Entry point
if __name__ == "__main__":
    app.run(debug=True)
