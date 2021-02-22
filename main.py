# -*- coding: utf-8 -*-
import ast
import hashlib
import statistics
from datetime import datetime

from bson.json_util import dumps
from bson.objectid import ObjectId
from flask import Flask
from flask import request, jsonify
from flask_bcrypt import Bcrypt
from flask_cors import CORS

from config import client
from utils import analyze_text, normalize_text_data

app = Flask(__name__)
CORS(app)

# Select the database
db = client.restfulapi
# Select the collection
texts_collection = db.texts
users_collection = db.users
results_collection = db.results

bcrypt = Bcrypt(app)


def normalize_result_data(data, remove_user=True):
    new_data = {x: data[x] for x in data if x not in "_id"}
    if remove_user:
        del new_data["user_id"]
    else:
        user = users_collection.find_one({"_id": ObjectId(data["user_id"])})
        print(user, user["login"])
        new_data["user"] = user["login"]
    new_data["id"] = data["_id"]["$oid"]
    new_data["wpm"] = {
        "story": []
    }
    for couple in data["wpmStats"]:
        for k, v in couple.items():
            duration = datetime.strptime(k, "%H:%M:%S:%f") - datetime.strptime(new_data["start"], "%H:%M:%S:%f")
            new_data["wpm"]["story"].append({
                "time": duration.total_seconds(),
                "wpm": v
            })
    seq = [x['wpm'] for x in new_data["wpm"]["story"]]
    new_data["wpm"]["min"] = min(seq)
    new_data["wpm"]["max"] = max(seq)
    new_data["wpm"]["average"] = statistics.mean(seq)
    new_data["wpm"]["median"] = statistics.median(seq)
    new_data["errors"] = []
    del new_data["wpmStats"]
    for couple in data["errorsStats"]:
        for k, v in couple.items():
            new_data["errors"].append({
                "word": k.strip(),
                "errors": v
            })
    del new_data["errorsStats"]
    duration = datetime.strptime(new_data["end"], "%H:%M:%S:%f") - datetime.strptime(new_data["start"], "%H:%M:%S:%f")
    new_data["time"] = duration.total_seconds()
    del new_data["start"]
    del new_data["end"]
    return new_data


@app.route("/")
def get_initial_response():
    return jsonify({
        'apiVersion': 'v1.0',
        'status': '200',
        'message': 'It\'s alive'
    })


@app.route("/api/v1/texts", methods=['POST'])
def create_text():
    try:
        try:
            body = ast.literal_eval(dumps(request.get_json()))
        except:
            return "", 400

        body["text_analysis"] = analyze_text(body["text"])
        body["created"] = datetime.utcnow().timestamp()
        body["updated"] = datetime.utcnow().timestamp()

        texts_collection.insert_one(body)

        return jsonify("Created successfully"), 201
    except Exception as err:
        print(err)
        return "", 500


@app.route("/api/v1/texts", methods=['GET'])
def fetch_texts():
    try:
        if texts_collection.find().count() > 0:
            raw_data = ast.literal_eval(dumps(texts_collection.find()))
            return jsonify([normalize_text_data(data) for data in raw_data])
        else:
            return jsonify([])

    except Exception as err:
        print(err)
        return "", 500


@app.route("/api/v1/texts/<text_id>", methods=['POST', 'PUT', 'UPDATE'])
def update_text(text_id):
    try:
        try:
            body = ast.literal_eval(dumps(request.get_json()))
        except:
            return "", 400

        old_record = texts_collection.find_one({"_id": ObjectId(text_id)})
        if old_record is None:
            return "", 404
        old_record = ast.literal_eval(dumps(old_record))
        buff = {**old_record, **body, "updated": datetime.utcnow().timestamp()}
        if old_record["text"] != buff["text"]:
            buff["text_analysis"] = analyze_text(body["text"])

        del buff["_id"]
        records_updated = texts_collection.update_one({"_id": ObjectId(text_id)}, {"$set": buff})

        if records_updated.modified_count > 0:
            return jsonify("Updated successfully"), 200
        else:
            return "", 404
    except Exception as err:
        print(err)
        return "", 500


@app.route("/api/v1/texts/<text_id>", methods=['DELETE'])
def remove_text(text_id):
    try:
        delete_text = texts_collection.delete_one({"_id": ObjectId(text_id)})

        if delete_text.deleted_count > 0:
            return jsonify("Deleted successfully"), 204
        else:
            return "", 404
    except Exception as err:
        print(err)
        return "", 500


@app.route("/api/v1/authorize", methods=["POST"])
def authorize():
    try:
        body = ast.literal_eval(dumps(request.get_json()))
    except:
        return jsonify("Bad request as the request body is not available"), 400

    user = users_collection.find_one({"login": body["login"]})
    if user is None:
        salt = "5gz"
        db_password = body["login"] + salt
        h = hashlib.md5(db_password.encode())
        body["token"] = h.hexdigest()
        body["password"] = str(bcrypt.generate_password_hash(body["password"]))
        body["password"] = body["password"][2: len(body["password"]) - 1]
        body["superuser"] = False
        users_collection.insert_one(body)
        return {"token": h.hexdigest(), "superuser": False}, 201
    if "password" in body:
        result = bcrypt.check_password_hash(user["password"], body["password"])
        if result:
            salt = "5gz"
            db_password = user["login"] + salt
            h = hashlib.md5(db_password.encode())
            user["token"] = h.hexdigest()
            users_collection.update_one({"_id": user["_id"]}, {"$set": {"token": h.hexdigest()}})
            return {"token": h.hexdigest(), "superuser": user["superuser"]}, 202
        return jsonify("Wrong password"), 403
    return jsonify("No password found"), 403


@app.route("/api/v1/results", methods=["POST"])
def save_race_result():
    if request.headers.get("Authorization"):
        token = request.headers.get("Authorization").split(" ")[1]
        user = users_collection.find_one({"token": token})
        if user is None:
            return jsonify("User not found"), 404
        try:
            body = ast.literal_eval(dumps(request.get_json()))
        except:
            return jsonify("Bad request as the request body is not available"), 400
        body["user_id"] = str(ObjectId(user["_id"]))
        results_collection.insert_one(body)
        return jsonify("Created successfully"), 201
    return jsonify("No auth has been provided"), 404


@app.route("/api/v1/my_results", methods=["GET"])
def fetch_race_results():
    if request.headers.get("Authorization"):
        token = request.headers.get("Authorization").split(" ")[1]
        user = users_collection.find_one({"token": token})
        if user is None:
            return jsonify("User not found"), 404
        try:
            results = results_collection.find({"user_id": str(ObjectId(user["_id"]))})
            if results.count() > 0:
                raw_data = ast.literal_eval(dumps(results))
                return jsonify([normalize_result_data(data) for data in raw_data])
            else:
                return jsonify([])
        except:
            return "", 500
    return jsonify("No auth has been provided"), 404


@app.route("/api/v1/results", methods=["GET"])
def fetch_race_results_all():
    if request.headers.get("Authorization"):
        token = request.headers.get("Authorization").split(" ")[1]
        user = users_collection.find_one({"token": token})
        if user is None:
            return jsonify("User not found"), 404
        try:
            results = results_collection.find()
            if results.count() > 0:
                raw_data = ast.literal_eval(dumps(results))
                return jsonify([normalize_result_data(data, remove_user=False) for data in raw_data])
            else:
                return jsonify([])
        except:
            return "", 500
    return jsonify("No auth has been provided"), 404


@app.errorhandler(404)
def page_not_found():
    return jsonify({
        "err":
            {
                "msg": "This route is currently not supported."
            }
    }), 404


if __name__ == '__main__':
    app.run(debug=True)
