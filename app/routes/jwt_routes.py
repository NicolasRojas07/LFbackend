from flask import Blueprint, request, jsonify, current_app
from bson import ObjectId
from bson.errors import InvalidId

from app.services.jwt_service import JWTService
from app.model.test_case_model import TestCase
from app import extensions

bp = Blueprint('jwt', __name__, url_prefix='/api/jwt')

@bp.route('/decode', methods=['POST'])
def decode():
    data = request.get_json() or {}
    token = data.get("token")
    if not token:
        return jsonify({"error": "Missing 'token' field"}), 400
    try:
        result = JWTService.decode_token_no_verify(token)
        is_valid_sem, sem_errors = JWTService.validate_semantics(result["header"], result["payload"])
        return jsonify({
            "header": result["header"],
            "payload": result["payload"],
            "signature_b64url": result["signature_b64url"],
            "semantic_valid": is_valid_sem,
            "semantic_errors": sem_errors
        })
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

@bp.route('/verify', methods=['POST'])
def verify():
    data = request.get_json() or {}
    token = data.get("token")
    secret = data.get("secret")
    algorithms = data.get("algorithms", current_app.config.get("ALLOWED_ALGORITHMS"))

    if not token or not secret:
        return jsonify({"error": "Missing 'token' or 'secret'"}), 400

    ok = JWTService.verify_signature(token, secret, algorithms=algorithms)
    return jsonify({"valid_signature": ok})

@bp.route('/encode', methods=['POST'])
def encode():
    data = request.get_json() or {}

    header = data.get("header", {})
    payload = data.get("payload", {})
    secret = data.get("secret")
    algorithm = data.get("algorithm", "HS256")

    if not secret:
        secret = current_app.config.get("APP_SECRET")
        if not secret:
            return jsonify({"error": "No secret provided and APP_SECRET is not configured"}), 400

    allowed = current_app.config.get("ALLOWED_ALGORITHMS", [])
    if algorithm not in allowed:
        return jsonify({
            "error": f"Invalid algorithm '{algorithm}'. Allowed algorithms: {allowed}"
        }), 400

    try:
        token = JWTService.create_token(header, payload, secret, algorithm)
        return jsonify({"token": token})
    except Exception as e:
        return jsonify({"error": f"Token generation failed: {str(e)}"}), 400


@bp.route('/save-test', methods=['POST'])
def save_test():
    data = request.get_json() or {}
    name = data.get("name")
    token = data.get("token")
    result = data.get("result", {})
    if not name or not token:
        return jsonify({"error": "Missing 'name' or 'token'"}), 400

    try:
        test_case = TestCase(name=name, description=data.get("description",""), token=token, result=result)
        collection = extensions.db.test_cases
        inserted = collection.insert_one(test_case.to_dict())
        return jsonify({"inserted_id": str(inserted.inserted_id), "success": True}), 201
    except Exception as e:
        return jsonify({"error": f"Failed to save test: {str(e)}"}), 500

@bp.route('/tests', methods=['GET'])
def list_tests():
    try:
        collection = extensions.db.test_cases
        cursor = collection.find().sort("created_at", -1)
        docs = []
        for d in cursor:
            d["id"] = str(d.pop("_id"))
            docs.append(d)
        return jsonify(docs), 200
    except Exception as e:
        print(f"Error fetching tests: {str(e)}")
        return jsonify([]), 200

@bp.route('/tests/<test_id>', methods=['DELETE'])
def delete_test(test_id):
    collection = extensions.db.test_cases
    try:
        res = collection.delete_one({"_id": ObjectId(test_id)})
    except InvalidId:
        return jsonify({"error": "Invalid test_id"}), 400
    return jsonify({"deleted_count": res.deleted_count})
