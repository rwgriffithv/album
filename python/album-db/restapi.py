from flask import Flask

_app = Flask(__name__)


@_app.route("/")
def hello_world():
    return "This is the Album backend!!"


if __name__ == "__main__":
    _app.run()
