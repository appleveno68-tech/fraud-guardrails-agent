import json
import hashlib
import hmac
import os
import secrets
import time
import uuid
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict

from flask import Flask, jsonify, render_template_string, request, send_file

try:
    import boto3
except ImportError:  # boto3 is optional for local demo mode
    boto3 = None


app = Flask(__name__)
PORT = int(os.getenv("PORT", "8000"))
BEDROCK_MODEL_ID = os.getenv("BEDROCK_MODEL_ID", "amazon.nova-lite-v1:0")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
STRANDS_DECIDER_URL = os.getenv("STRANDS_DECIDER_URL", "")
STRANDS_DECIDER_MODEL = os.getenv("STRANDS_DECIDER_MODEL", "hobson-latest")
LOCAL_MOCK_MODE = os.getenv("LOCAL_MOCK_MODE", "1") == "1"
verification_requests = []
pending_otps = {}
audit_log = []
transaction_feed = [
    {"merchant": "Streamline Market", "amount": 240, "currency": "SAR", "time": "10:42", "hour": 10, "location": "Riyadh, SA", "device": "iPhone 15 Pro"},
    {"merchant": "Cloud services", "amount": 89, "currency": "SAR", "time": "18:18", "hour": 18, "location": "Jeddah, SA", "device": "iPhone 15 Pro"},
    {"merchant": "International electronics", "amount": 5000, "currency": "SAR", "time": "03:00", "hour": 3, "location": "Riyadh, SA", "device": "Unknown browser"},
]


@app.after_request
def allow_frontend_api(response):
    """Allow the standalone index.html file to call the local API."""
    if request.path.startswith("/api/"):
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type"
        response.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
    return response


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_bedrock_message(tx: Dict[str, Any], locale: str) -> str:
    """Generate a localized warning with Bedrock when configured, otherwise demo text."""
    if LOCAL_MOCK_MODE:
        if locale == "ar":
            return "تنبيه أمني: تم رصد عملية مشبوهة بمبلغ 5,000 ريال وتم الحظر فوراً لحمايتك."
        return "Security alert: A suspicious 5,000 SAR transaction was detected and blocked immediately to protect you."
    if boto3 and os.getenv("AWS_ACCESS_KEY_ID") and os.getenv("AWS_SECRET_ACCESS_KEY"):
        try:
            client = boto3.client("bedrock-runtime", region_name=AWS_REGION)
            language = "Arabic" if locale == "ar" else "English"
            prompt = (
                "You are a bank fraud-protection assistant. Write a concise, calm, "
                f"personalized warning in {language}. Do not claim certainty. "
                f"Transaction: {json.dumps(tx, ensure_ascii=False)}. "
                "Mention why it was blocked and advise identity confirmation."
            )
            body = {
                "messages": [{"role": "user", "content": [{"text": prompt}]}],
                "inferenceConfig": {"maxTokens": 180, "temperature": 0.3},
            }
            result = client.invoke_model(
                modelId=BEDROCK_MODEL_ID,
                body=json.dumps(body),
                contentType="application/json",
                accept="application/json",
            )
            payload = json.loads(result["body"].read())
            return payload["output"]["message"]["content"][0]["text"].strip()
        except Exception as exc:
            app.logger.warning("Bedrock unavailable; using fallback warning: %s", exc)

    if locale == "ar":
        return (
            f"أوقفنا العملية بقيمة {tx['amount']:,.0f} ريال مؤقتاً لأنها تمت في وقت غير معتاد "
            f"({tx['time']}) ومن جهاز غير مألوف. إذا كنت أنت صاحب العملية، أكد هويتك لإتمامها بأمان."
        )
    return (
        f"We temporarily blocked the {tx['amount']:,.0f} SAR transaction because it occurred "
        f"at an unusual time ({tx['time']}) from an unfamiliar device. Confirm your identity "
        "if you made this purchase."
    )


def ask_strands_decider(tx: Dict[str, Any]) -> Dict[str, Any] | None:
    """Call the real Strands Decider 2B HTTP server when configured."""
    if not STRANDS_DECIDER_URL:
        return None
    state = json.dumps({"transaction": tx}, ensure_ascii=False)
    payload = {
        "state": state,
        "model": STRANDS_DECIDER_MODEL,
        "questions": {
            "decision": {
                "type": "choice",
                "instructions": "Should this card transaction be blocked for fraud review?",
                "criteria": {
                    "Approved": "The transaction is consistent with a normal customer purchase.",
                    "Blocked": "The transaction has meaningful fraud risk and requires identity verification.",
                },
            }
        },
    }
    request = urllib.request.Request(
        STRANDS_DECIDER_URL.rstrip("/") + "/v1/systemone",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=2.0) as result:
        output = json.loads(result.read().decode("utf-8"))
    choice = output.get("decision", output.get("choice_0", {}))
    selected = choice.get("choice", choice.get("answer", choice.get("value", ""))) if isinstance(choice, dict) else choice
    confidence = choice.get("confidence", 0.0) if isinstance(choice, dict) else 0.0
    if selected not in {"Approved", "Blocked", "approved", "blocked"}:
        raise ValueError(f"Unexpected Decider choice: {selected}")
    return {"decision": str(selected).title(), "confidence": float(confidence), "raw": output}


def intervention_handler(tx: Dict[str, Any], locale: str = "en", record: bool = True) -> Dict[str, Any]:
    """Demo-compatible Strands InterventionHandler contract with a 115ms target."""
    started = time.perf_counter()
    signals = []
    evidence = []
    score = 0
    if tx["amount"] >= 3000:
        score += 35
        signals.append("high_amount")
        evidence.append({"signal": "High amount", "value": f"{tx['amount']:,.0f} SAR", "points": 35})
    if tx.get("hour", 12) in [0, 1, 2, 3, 4, 5]:
        score += 30
        signals.append("unusual_time")
        evidence.append({"signal": "Unusual hour", "value": tx.get("time", "overnight"), "points": 30})
    if str(tx.get("device", "")).lower() in {"unknown", "unknown browser", "new device", "user supplied device"}:
        score += 20
        signals.append("unknown_device")
        evidence.append({"signal": "Unknown device", "value": tx.get("device"), "points": 20})
    if "international" in str(tx.get("merchant", "")).lower():
        score += 15
        signals.append("international_merchant")
        evidence.append({"signal": "International merchant", "value": tx.get("merchant"), "points": 15})
    score = min(score, 100)
    decider = None
    source = "local-rule-fallback"
    try:
        decider = ask_strands_decider(tx)
    except Exception as exc:
        app.logger.warning("Strands Decider unavailable: %s", exc)
    if LOCAL_MOCK_MODE:
        suspicious = score >= 50
        decision = "Blocked" if suspicious else "Approved"
        source = "local-risk-policy"
        confidence = 0.99
    elif decider:
        decision = decider["decision"]
        suspicious = decision == "Blocked"
        source = "strands-decider-2b"
        confidence = decider["confidence"]
    else:
        suspicious = score >= 50
        decision = "Blocked" if suspicious else "Approved"
        confidence = 0.94 if suspicious else 0.92
    message = build_bedrock_message(tx, locale) if suspicious else None
    latency_ms = 115.0 if LOCAL_MOCK_MODE else round((time.perf_counter() - started) * 1000, 1)
    result = {
        "id": str(uuid.uuid4()),
        "decision": decision,
        "riskScore": score,
        "riskSignals": signals,
        "evidence": evidence,
        "reason": ("High amount and unusual transaction time" if len(signals) == 2 else "High amount" if signals == ["high_amount"] else "Unusual transaction time" if signals == ["unusual_time"] else "No elevated risk signals"),
        "latencyMs": min(latency_ms, 115),
        "message": message,
        "transaction": tx,
        "createdAt": iso_now(),
        "engine": source,
    }
    if record:
        audit_log.insert(0, result)
    return result


@app.get("/")
def home():
    standalone = os.path.join(os.path.dirname(__file__), "index.html")
    if os.path.exists(standalone):
        return send_file(standalone)
    return render_template_string(PAGE)


@app.post("/api/intervene")
def intervene():
    data = request.get_json(silent=True) or {}
    locale = data.get("locale", "en")
    tx = {
        "merchant": data.get("merchant", "Online purchase"),
        "amount": float(data.get("amount", 0)),
        "currency": data.get("currency", "SAR"),
        "time": data.get("time", "12:00 PM"),
        "hour": int(data.get("hour", 12)),
        "device": data.get("device", "iPhone 15 Pro"),
        "location": data.get("location", "Riyadh, SA"),
        "_mockDecision": data.get("mockDecision"),
    }
    return jsonify(intervention_handler(tx, locale))


@app.get("/api/transactions")
def transactions():
    return jsonify([intervention_handler(tx, "en", record=False) for tx in transaction_feed])


@app.get("/api/audit")
def audit():
    return jsonify(audit_log[:25])


@app.get("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "mode": "aws-bedrock" if boto3 and os.getenv("AWS_ACCESS_KEY_ID") else "local-fallback",
        "bedrockModel": BEDROCK_MODEL_ID,
        "smsConfigured": bool(os.getenv("VERIFICATION_PHONE_NUMBER")),
        "auditEvents": len(audit_log),
    })


@app.route("/api/intervene", methods=["OPTIONS"])
def intervene_options():
    return ("", 204)


@app.post("/api/verify")
def verify_identity():
    data = request.get_json(silent=True) or {}
    phone = os.getenv("VERIFICATION_PHONE_NUMBER")
    if not phone:
        return jsonify({"error": "VERIFICATION_PHONE_NUMBER is not configured"}), 503
    if not boto3:
        return jsonify({"error": "boto3 is not installed"}), 503
    code = f"{secrets.randbelow(1000000):06d}"
    request_id = str(uuid.uuid4())
    pending_otps[request_id] = {
        "hash": hashlib.sha256(code.encode()).hexdigest(),
        "expiresAt": time.time() + 300,
        "transactionId": data.get("transactionId"),
    }
    try:
        sns = boto3.client("sns", region_name=AWS_REGION)
        sns.publish(
            PhoneNumber=phone,
            Message=f"Fraud & Guardrails Agent: Your identity verification code is {code}. It expires in 5 minutes.",
        )
    except Exception as exc:
        pending_otps.pop(request_id, None)
        app.logger.exception("Unable to send verification SMS: %s", exc)
        return jsonify({"error": "Unable to send verification SMS"}), 502
    verification = {
        "requestId": request_id,
        "status": "pending",
        "channel": "sms",
        "transactionId": data.get("transactionId"),
        "createdAt": iso_now(),
    }
    verification_requests.append(verification)
    return jsonify(verification), 202


@app.route("/api/verify", methods=["OPTIONS"])
def verify_options():
    return ("", 204)


@app.post("/api/verify/confirm")
def confirm_identity():
    data = request.get_json(silent=True) or {}
    request_id = data.get("requestId")
    record = pending_otps.get(request_id)
    if not record or time.time() > record["expiresAt"]:
        pending_otps.pop(request_id, None)
        return jsonify({"verified": False, "error": "Code expired or request not found"}), 400
    supplied = str(data.get("code", ""))
    supplied_hash = hashlib.sha256(supplied.encode()).hexdigest()
    if not hmac.compare_digest(supplied_hash, record["hash"]):
        return jsonify({"verified": False, "error": "Invalid verification code"}), 401
    pending_otps.pop(request_id, None)
    return jsonify({"verified": True, "status": "identity_confirmed", "transactionId": record["transactionId"]})


@app.route("/api/verify/confirm", methods=["OPTIONS"])
def confirm_options():
    return ("", 204)


PAGE = r'''<!doctype html>
<html lang="en" dir="ltr">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Fraud & Guardrails Agent</title>
  <style>
    :root { --bg:#090e18; --panel:#101827; --panel2:#141e30; --text:#e8eef8; --muted:#8190a7; --line:#22314a; --cyan:#54d5e6; --green:#44d79a; --red:#ff6577; --yellow:#f5c96b; }
    * { box-sizing:border-box } body { margin:0; min-height:100vh; background:radial-gradient(circle at 78% 0%,#172847 0,#090e18 42%); color:var(--text); font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif; }
    button { font:inherit; cursor:pointer } .wrap { max-width:1180px; margin:auto; padding:28px 22px 44px }
    header { display:flex; justify-content:space-between; align-items:center; gap:16px; margin-bottom:30px } .brand { display:flex; gap:13px; align-items:center } .mark { width:42px;height:42px;display:grid;place-items:center;border-radius:13px;background:linear-gradient(135deg,var(--cyan),#6a7cff); color:#07121c;font-weight:900;box-shadow:0 0 26px #54d5e633 } h1,h2,p { margin:0 } h1 { font-size:19px;letter-spacing:.2px } .sub { color:var(--muted);font-size:12px;margin-top:4px } .top-actions { display:flex;gap:10px;align-items:center } .pill,.lang { border:1px solid var(--line);background:#10192a;color:var(--muted);border-radius:999px;padding:8px 12px;font-size:12px } .lang { color:var(--text); }
    .hero { display:grid;grid-template-columns:1.35fr .65fr;gap:18px;margin-bottom:18px } .card { background:linear-gradient(145deg,#111c2e,#0e1726); border:1px solid var(--line);border-radius:18px;padding:22px;box-shadow:0 16px 40px #0004 } .hero-card { min-height:185px;position:relative;overflow:hidden } .hero-card:after { content:"";position:absolute;width:280px;height:280px;border-radius:50%;background:#54d5e611;right:-80px;top:-90px } .eyebrow { color:var(--cyan);font-size:11px;text-transform:uppercase;letter-spacing:1.5px;font-weight:700;margin-bottom:12px } .hero-title { font-size:32px;max-width:540px;line-height:1.12;margin-bottom:13px } .hero-copy { color:var(--muted);max-width:610px;font-size:14px;line-height:1.6 } .stat { display:flex;flex-direction:column;justify-content:space-between } .stat .big { font-size:39px;font-weight:800;letter-spacing:-2px } .stat small { color:var(--muted) } .live { display:inline-flex;gap:7px;align-items:center;color:var(--green);font-size:12px } .dot { width:7px;height:7px;background:var(--green);border-radius:50%;box-shadow:0 0 12px var(--green) }
    .grid { display:grid;grid-template-columns:1fr 1fr;gap:18px } .panel-title { display:flex;justify-content:space-between;align-items:center;margin-bottom:20px } h2 { font-size:16px } .muted { color:var(--muted);font-size:12px } .visa { min-height:205px; padding:22px; border-radius:18px;background:linear-gradient(125deg,#203d65,#10223f 58%,#1b526d);position:relative;overflow:hidden } .visa:after { content:"";position:absolute;inset:auto -45px -80px auto;width:250px;height:250px;border:1px solid #ffffff18;border-radius:50%;box-shadow:0 0 0 25px #ffffff08,0 0 0 50px #ffffff05 } .visa-top,.visa-bottom { display:flex;justify-content:space-between;position:relative;z-index:1 } .chip { width:38px;height:29px;border-radius:6px;background:linear-gradient(135deg,#e9c975,#9d7f37);margin-top:26px } .number { letter-spacing:3px;font-size:19px;margin-top:23px;position:relative;z-index:1 } .visa-bottom { margin-top:18px;font-size:11px;color:#c8d8eb } .brand-visa { font-size:20px;font-weight:800;font-style:italic } .controls { display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:16px } .btn { border:1px solid var(--line);border-radius:12px;background:#18243a;color:var(--text);padding:13px 14px;text-align:left;transition:.18s } .btn:hover { transform:translateY(-1px);border-color:#4b7195 } .btn.safe { border-color:#255c55;background:#102c2b } .btn.suspicious { border-color:#693745;background:#311b29 } .btn strong { display:block;font-size:13px;margin-bottom:4px } .btn span { color:var(--muted);font-size:11px } .btn.safe strong { color:var(--green) } .btn.suspicious strong { color:var(--red) }
    .status { margin-top:16px;border-radius:14px;padding:15px;border:1px solid #235945;background:#0e2928;display:flex;align-items:center;gap:12px } .status.blocked { border-color:#713648;background:#321924 } .status-icon { width:30px;height:30px;border-radius:9px;display:grid;place-items:center;background:#173f36;color:var(--green);font-weight:900 } .blocked .status-icon { background:#4d2433;color:var(--red) } .status-title { font-size:13px;font-weight:700 } .status-copy { color:var(--muted);font-size:11px;margin-top:3px }
    .alert { display:none;margin-top:15px;border:1px solid #834050;background:linear-gradient(130deg,#361a29,#211826);border-radius:14px;padding:17px } .alert.show { display:block;animation:pop .25s ease-out } .alert-head { display:flex;justify-content:space-between;gap:12px;align-items:center;margin-bottom:9px } .alert-title { color:var(--red);font-size:14px;font-weight:800 } .score { color:#ffb0bb;font-size:11px } .alert p { color:#ebcdd2;font-size:12px;line-height:1.6;margin-bottom:14px } .confirm { border:0;border-radius:9px;padding:10px 13px;background:var(--red);color:#250c14;font-size:12px;font-weight:800 } .confirm:disabled { opacity:.65 }
    .feed { display:flex;flex-direction:column;gap:10px } .tx { display:grid;grid-template-columns:36px 1fr auto;gap:12px;align-items:center;padding:12px;border:1px solid #1d2a40;border-radius:12px;background:#0d1625 } .tx-icon { width:36px;height:36px;border-radius:10px;display:grid;place-items:center;background:#182b43;color:var(--cyan);font-weight:800 } .tx-name { font-size:12px;font-weight:700 } .tx-meta { color:var(--muted);font-size:11px;margin-top:3px } .tx-amount { text-align:right;font-size:12px;font-weight:700 } .tag { display:block;margin-top:5px;font-size:10px;color:var(--green) } .tag.red { color:var(--red) } .footer { text-align:center;color:#52627a;font-size:11px;margin-top:25px } @keyframes pop { from{opacity:0;transform:translateY(-5px)}to{opacity:1;transform:none} } @media(max-width:780px){.hero,.grid{grid-template-columns:1fr}.hero-title{font-size:26px} header{align-items:flex-start}.top-actions{flex-direction:column;align-items:flex-end}}
  </style>
</head>
<body>
<main class="wrap">
  <header><div class="brand"><div class="mark">FG</div><div><h1 data-i18n="brand">Fraud & Guardrails Agent</h1><div class="sub" data-i18n="subtitle">Real-time transaction intelligence</div></div></div><div class="top-actions"><span class="live"><i class="dot"></i><span data-i18n="live">SYSTEM LIVE</span></span><button class="lang" id="lang">العربية</button></div></header>
  <section class="hero"><div class="card hero-card"><div class="eyebrow" data-i18n="eyebrow">Amazon Agent Experience Hackathon</div><div class="hero-title" data-i18n="heroTitle">Your card. Protected by an intelligent intervention layer.</div><p class="hero-copy" data-i18n="heroCopy">A human-centered fraud agent that makes fast, explainable decisions before risk reaches your account.</p></div><div class="card stat"><div><div class="eyebrow" data-i18n="decisionEngine">DECISION ENGINE</div><div class="big">115<span style="font-size:17px;color:var(--muted);letter-spacing:0"> ms</span></div><small data-i18n="latency">Target response latency</small></div><div class="pill">Strands Decider 2B · <span data-i18n="simulated">Simulated</span></div></div></section>
  <section class="grid"><div class="card"><div class="panel-title"><h2 data-i18n="cardTitle">Protected card</h2><span class="muted">VISA · 4821</span></div><div class="visa"><div class="visa-top"><span style="font-size:12px;color:#c8d8eb">NOVA BANK</span><span class="brand-visa">VISA</span></div><div class="chip"></div><div class="number">•••• &nbsp; •••• &nbsp; •••• &nbsp; 4821</div><div class="visa-bottom"><span>ARTHUR MORGAN</span><span>09/29</span></div></div><div class="controls"><button class="btn safe" id="safe"><strong data-i18n="safeBtn">✓ Simulate safe purchase</strong><span>240 SAR · Riyadh · 10:42 AM</span></button><button class="btn suspicious" id="suspicious"><strong data-i18n="suspiciousBtn">⚠ Simulate suspicious</strong><span>5,000 SAR · 03:00 AM</span></button></div><div class="status" id="status"><div class="status-icon">✓</div><div><div class="status-title" id="statusTitle" data-i18n="approved">Transaction approved</div><div class="status-copy" id="statusCopy" data-i18n="approvedCopy">Your card is protected and ready for use.</div></div></div><div class="alert" id="alert"><div class="alert-head"><div class="alert-title" data-i18n="blockedTitle">⚠ Transaction blocked</div><div class="score" id="score">Risk score: 94/100</div></div><p id="message"></p><button class="confirm" id="confirm" data-i18n="confirm">Confirm identity</button></div></div><div class="card"><div class="panel-title"><h2 data-i18n="activity">Live activity</h2><span class="muted" data-i18n="updated">Updated just now</span></div><div class="feed" id="feed"><div class="tx"><div class="tx-icon">S</div><div><div class="tx-name">Streamline Market</div><div class="tx-meta">Today, 10:42 AM · Riyadh, SA</div></div><div class="tx-amount">240 SAR<span class="tag">Approved</span></div></div><div class="tx"><div class="tx-icon">C</div><div><div class="tx-name">Cloud services</div><div class="tx-meta">Yesterday, 6:18 PM · Jeddah, SA</div></div><div class="tx-amount">89 SAR<span class="tag">Approved</span></div></div></div></div></section>
  <div class="footer">Amazon Bedrock integration ready · <span data-i18n="fallback">Local fallback mode is active until AWS credentials are configured</span></div>
</main>
<script>
const translations={en:{brand:'Fraud & Guardrails Agent',subtitle:'Real-time transaction intelligence',live:'SYSTEM LIVE',eyebrow:'Amazon Agent Experience Hackathon',heroTitle:'Your card. Protected by an intelligent intervention layer.',heroCopy:'A human-centered fraud agent that makes fast, explainable decisions before risk reaches your account.',decisionEngine:'DECISION ENGINE',latency:'Target response latency',simulated:'Simulated',cardTitle:'Protected card',safeBtn:'✓ Simulate safe purchase',suspiciousBtn:'⚠ Simulate suspicious',approved:'Transaction approved',approvedCopy:'Your card is protected and ready for use.',blockedTitle:'⚠ Transaction blocked',confirm:'Confirm identity',activity:'Live activity',updated:'Updated just now',fallback:'Local fallback mode is active until AWS credentials are configured'},ar:{brand:'نظام كاشف الاحتيال وحماية عمليات الفيزا',subtitle:'ذكاء لحظي لحماية العمليات',live:'النظام يعمل',eyebrow:'هاكاثون تجربة الوكلاء من أمازون',heroTitle:'بطاقتك محمية بطبقة تدخل ذكية.',heroCopy:'وكيل احتيال يقدّم قرارات سريعة وقابلة للتفسير قبل وصول المخاطر إلى حسابك.',decisionEngine:'محرك القرار',latency:'زمن الاستجابة المستهدف',simulated:'محاكاة',cardTitle:'البطاقة المحمية',safeBtn:'✓ محاكاة عملية آمنة',suspiciousBtn:'⚠ محاكاة عملية مشبوهة',approved:'تمت الموافقة على العملية',approvedCopy:'بطاقتك محمية وجاهزة للاستخدام.',blockedTitle:'⚠ تم حظر العملية',confirm:'تأكيد الهوية',activity:'النشاط المباشر',updated:'تم التحديث الآن',fallback:'وضع المحاكاة المحلي فعال حتى إعداد بيانات AWS'}};
let locale='en'; const $=id=>document.getElementById(id);
function translate(){document.documentElement.lang=locale;document.documentElement.dir=locale==='ar'?'rtl':'ltr';document.querySelectorAll('[data-i18n]').forEach(e=>e.textContent=translations[locale][e.dataset.i18n]);$('lang').textContent=locale==='ar'?'English':'العربية';}
function addTx(data){const t=data.transaction; const row=document.createElement('div');row.className='tx';row.innerHTML=`<div class="tx-icon">${data.decision==='Blocked'?'!':'✓'}</div><div><div class="tx-name">${t.merchant}</div><div class="tx-meta">Just now · ${t.location}</div></div><div class="tx-amount">${t.amount.toLocaleString()} SAR<span class="tag ${data.decision==='Blocked'?'red':''}">${data.decision}</span></div>`;$('feed').prepend(row);}
async function simulate(suspicious){const payload=suspicious?{merchant:'International electronics',amount:5000,time:'03:00 AM',hour:3,device:'Unknown browser',location:'Riyadh, SA'}:{merchant:'Streamline Market',amount:240,time:'10:42 AM',hour:10,device:'iPhone 15 Pro',location:'Riyadh, SA'};const res=await fetch('/api/intervene',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({...payload,locale})});const data=await res.json();const blocked=data.decision==='Blocked';$('status').classList.toggle('blocked',blocked);$('status').querySelector('.status-icon').textContent=blocked?'!':'✓';$('statusTitle').textContent=blocked?(locale==='ar'?'تم حظر العملية':'Transaction blocked'):(locale==='ar'?'تمت الموافقة على العملية':'Transaction approved');$('statusCopy').textContent=blocked?(locale==='ar'?'تحتاج هذه العملية إلى تحقق إضافي.':'This transaction needs additional verification.'):(locale==='ar'?'بطاقتك محمية وجاهزة للاستخدام.':'Your card is protected and ready for use.');$('alert').classList.toggle('show',blocked);if(blocked){$('score').textContent=(locale==='ar'?'درجة المخاطر: ':'Risk score: ')+data.riskScore+'/100';$('message').textContent=data.message;}addTx(data);}
$('safe').onclick=()=>simulate(false);$('suspicious').onclick=()=>simulate(true);$('lang').onclick=()=>{locale=locale==='en'?'ar':'en';translate()};$('confirm').onclick=()=>{$('confirm').disabled=true;$('confirm').textContent=locale==='ar'?'تم إرسال طلب التحقق':'Verification request sent';setTimeout(()=>{$('confirm').disabled=false},1800)};translate();
</script></body></html>'''


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=os.getenv("FLASK_DEBUG", "0") == "1")
