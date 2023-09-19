from flask import Flask

_app = Flask(__name__)


_users = {"ZC": {"id": 0, "location": "MA"}, "RG": {"id": 0, "location": "CA"}}


@_app.route("/")
def hello_world():
    return "This is the Album backend!!"


@_app.route("/user")
def user_list():
    return [uname for uname in _users.keys()]


@_app.route("/user/<username>")
def user_att(username):
    att = _users[username]
    return att if att else {}


if __name__ == "__main__":
    _app.run()
