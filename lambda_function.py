import hashlib
import json
import os
import secrets
import time
import uuid

import boto3

TABLE = boto3.resource("dynamodb").Table(os.environ["AUDIT_TABLE"])
MODEL_ID = os.getenv("BEDROCK_MODEL_ID", "amazon.nova-lite-v1:0")


def response(status, body):
    return {"statusCode": status, "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"}, "body": json.dumps(body, ensure_ascii=False)}


def warning(tx, locale):
    language = "Arabic" if locale == "ar" else "English"
    prompt = f"Write a concise bank fraud warning in {language}. Do not claim certainty. Transaction: {json.dumps(tx)}. Ask the user to verify identity."
    client = boto3.client("bedrock-runtime")
    result = client.converse(modelId=MODEL_ID, messages=[{"role": "user", "content": [{"text": prompt}]}], inferenceConfig={"maxTokens": 180, "temperature": 0.2})
    return result["output"]["message"]["content"][0]["text"]


def decide(tx, locale):
    signals = []
    if float(tx.get("amount", 0)) >= 3000:
        signals.append("high_amount")
    if int(tx.get("hour", 12)) in [0, 1, 2, 3, 4, 5]:
        signals.append("unusual_time")
    blocked = bool(signals)
    result = {"id": str(uuid.uuid4()), "decision": "Blocked" if blocked else "Approved", "riskScore": 94 if blocked else 8, "riskSignals": signals, "transaction": tx, "createdAt": int(time.time())}
    if blocked:
        try:
            result["message"] = warning(tx, locale)
        except Exception:
            result["message"] = "This transaction was blocked because it contains elevated risk signals. Confirm your identity if you made this purchase."
    TABLE.put_item(Item={"id": result["id"], "payload": result})
    return result


def handler(event, context):
    path = event.get("path", "")
    method = event.get("httpMethod", "GET")
    body = json.loads(event.get("body") or "{}")
    if path.endswith("/intervene") and method == "POST":
        return response(200, decide(body, body.get("locale", "en")))
    if path.endswith("/audit") and method == "GET":
        items = TABLE.scan(Limit=25).get("Items", [])
        return response(200, items)
    if path.endswith("/verify") and method == "POST":
        phone = os.getenv("VERIFICATION_PHONE_NUMBER")
        if not phone:
            return response(503, {"error": "VERIFICATION_PHONE_NUMBER is not configured"})
        request_id = str(uuid.uuid4())
        code = f"{secrets.randbelow(1000000):06d}"
        TABLE.put_item(Item={"id": request_id, "type": "otp", "otpHash": hashlib.sha256(code.encode()).hexdigest(), "expiresAt": int(time.time()) + 300})
        boto3.client("sns").publish(PhoneNumber=phone, Message=f"Your verification code is {code}. It expires in 5 minutes.")
        return response(202, {"requestId": request_id, "status": "pending"})
    if path.endswith("/verify/confirm") and method == "POST":
        record = TABLE.get_item(Key={"id": body.get("requestId")}).get("Item")
        if not record or record.get("type") != "otp" or int(record.get("expiresAt", 0)) < int(time.time()):
            return response(400, {"verified": False, "error": "Code expired or request not found"})
        supplied = hashlib.sha256(str(body.get("code", "")).encode()).hexdigest()
        if supplied != record.get("otpHash"):
            return response(401, {"verified": False, "error": "Invalid verification code"})
        TABLE.delete_item(Key={"id": body.get("requestId")})
        return response(200, {"verified": True, "status": "identity_confirmed"})
    return response(404, {"error": "Not found"})
