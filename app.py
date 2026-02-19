from flask import Flask, render_template, request, send_file
import pandas as pd
import networkx as nx
import json
import os
import time
from collections import defaultdict

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
OUTPUT_FOLDER = "outputs"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


# ---------------- DETECTION FUNCTIONS ---------------- #

def detect_cycles(G):
    all_cycles = list(nx.simple_cycles(G))
    return [c for c in all_cycles if 3 <= len(c) <= 5]


def detect_fan_patterns(G):
    fan_patterns = defaultdict(list)

    for node in G.nodes():
        if G.in_degree(node) >= 10:
            fan_patterns[node].append("fan_in")

        if G.out_degree(node) >= 10:
            fan_patterns[node].append("fan_out")

    return fan_patterns


def calculate_score(patterns):
    score = 0

    if any("cycle" in p for p in patterns):
        score += 50
    if "fan_in" in patterns:
        score += 20
    if "fan_out" in patterns:
        score += 20

    return float(min(score, 100))


# ---------------- ROUTES ---------------- #

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload_file():
    file = request.files["file"]
    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)

    start_time = time.time()

    df = pd.read_csv(filepath)

    required_columns = {"transaction_id", "sender_id", "receiver_id", "amount", "timestamp"}
    if not required_columns.issubset(df.columns):
        return "Invalid CSV format. Please follow required structure."

    G = nx.DiGraph()

    for _, row in df.iterrows():
        G.add_edge(row["sender_id"], row["receiver_id"])

    suspicious_dict = defaultdict(list)
    fraud_rings = []

    # -------- Cycle Detection -------- #
    cycles = detect_cycles(G)

    ring_counter = 1

    for cycle in cycles:
        ring_id = f"RING_{ring_counter:03d}"

        fraud_rings.append({
            "ring_id": ring_id,
            "member_accounts": cycle,
            "pattern_type": "cycle",
            "risk_score": 95.0
        })

        for account in cycle:
            suspicious_dict[account].append(f"cycle_length_{len(cycle)}")

        ring_counter += 1

    # -------- Fan Patterns -------- #
    fan_patterns = detect_fan_patterns(G)

    for account, patterns in fan_patterns.items():
        suspicious_dict[account].extend(patterns)

    # -------- Build suspicious_accounts JSON -------- #
    suspicious_accounts = []

    for account, patterns in suspicious_dict.items():
        suspicion_score = calculate_score(patterns)

        # Find ring_id (if part of cycle)
        ring_id = "N/A"
        for ring in fraud_rings:
            if account in ring["member_accounts"]:
                ring_id = ring["ring_id"]
                break

        suspicious_accounts.append({
            "account_id": account,
            "suspicion_score": suspicion_score,
            "detected_patterns": list(set(patterns)),
            "ring_id": ring_id
        })

    # Sort descending
    suspicious_accounts = sorted(
        suspicious_accounts,
        key=lambda x: x["suspicion_score"],
        reverse=True
    )

    processing_time = round(time.time() - start_time, 2)

    result_json = {
        "suspicious_accounts": suspicious_accounts,
        "fraud_rings": fraud_rings,
        "summary": {
            "total_accounts_analyzed": len(G.nodes()),
            "suspicious_accounts_flagged": len(suspicious_accounts),
            "fraud_rings_detected": len(fraud_rings),
            "processing_time_seconds": processing_time
        }
    }

    output_path = os.path.join(OUTPUT_FOLDER, "result.json")

    with open(output_path, "w") as f:
        json.dump(result_json, f, indent=4)

    return render_template(
        "results.html",
        fraud_rings=fraud_rings,
        suspicious_accounts=suspicious_accounts
    )


@app.route("/download")
def download_file():
    return send_file("outputs/result.json", as_attachment=True)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
