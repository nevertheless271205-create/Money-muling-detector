# Money-muling-
pip install -r requirements.txt
import streamlit as st
import pandas as pd
import networkx as nx
import json
import time
from datetime import datetime, timedelta
from pyvis.network import Network
import tempfile

# -------------------------------
# Helper Functions
# -------------------------------

def parse_timestamp(ts):
    return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")


def build_graph(df):
    G = nx.DiGraph()
    for _, row in df.iterrows():
        sender = row["sender_id"]
        receiver = row["receiver_id"]
        amount = float(row["amount"])
        timestamp = parse_timestamp(row["timestamp"])

        G.add_node(sender)
        G.add_node(receiver)

        G.add_edge(sender, receiver, amount=amount, timestamp=timestamp)

    return G


def detect_cycles(G, min_len=3, max_len=5):
    cycles = list(nx.simple_cycles(G))
    valid_cycles = [c for c in cycles if min_len <= len(c) <= max_len]
    return valid_cycles


def detect_fan_in_out(df, window_hours=72, threshold=10):
    suspicious = {}
    patterns = {}

    df["timestamp_dt"] = df["timestamp"].apply(parse_timestamp)

    for acc in pd.concat([df["sender_id"], df["receiver_id"]]).unique():
        incoming = df[df["receiver_id"] == acc]
        outgoing = df[df["sender_id"] == acc]

        # FAN-IN (many senders to one receiver in time window)
        if len(incoming) >= threshold:
            incoming_sorted = incoming.sort_values("timestamp_dt")
            time_span = incoming_sorted["timestamp_dt"].max() - incoming_sorted["timestamp_dt"].min()

            if time_span <= timedelta(hours=window_hours):
                suspicious[acc] = suspicious.get(acc, 0) + 25
                patterns.setdefault(acc, []).append("fan_in_smurfing")

        # FAN-OUT (one sender to many receivers in time window)
        if len(outgoing) >= threshold:
            outgoing_sorted = outgoing.sort_values("timestamp_dt")
            time_span = outgoing_sorted["timestamp_dt"].max() - outgoing_sorted["timestamp_dt"].min()

            if time_span <= timedelta(hours=window_hours):
                suspicious[acc] = suspicious.get(acc, 0) + 25
                patterns.setdefault(acc, []).append("fan_out_smurfing")

    return suspicious, patterns


def detect_shell_chains(G, min_hops=3):
    suspicious = {}
    patterns = {}
    rings = []

    nodes = list(G.nodes())

    for start in nodes:
        for end in nodes:
            if start != end:
                try:
                    path = nx.shortest_path(G, start, end)
                    if len(path) >= min_hops + 1:  # nodes = hops+1
                        intermediate = path[1:-1]

                        # intermediate nodes should have low degree
                        low_degree_nodes = []
                        for node in intermediate:
                            deg = G.in_degree(node) + G.out_degree(node)
                            if 2 <= deg <= 3:
                                low_degree_nodes.append(node)

                        if len(low_degree_nodes) == len(intermediate) and len(intermediate) > 0:
                            rings.append(path)

                            for node in intermediate:
                                suspicious[node] = suspicious.get(node, 0) + 20
                                patterns.setdefault(node, []).append("layered_shell_chain")

                except:
                    continue

    return suspicious, patterns, rings


def compute_velocity_scores(df, threshold_tx=15, window_hours=24):
    suspicious = {}
    patterns = {}

    df["timestamp_dt"] = df["timestamp"].apply(parse_timestamp)

    for acc in pd.concat([df["sender_id"], df["receiver_id"]]).unique():
        related = df[(df["sender_id"] == acc) | (df["receiver_id"] == acc)]
        if len(related) >= threshold_tx:
            related_sorted = related.sort_values("timestamp_dt")
            time_span = related_sorted["timestamp_dt"].max() - related_sorted["timestamp_dt"].min()

            if time_span <= timedelta(hours=window_hours):
                suspicious[acc] = suspicious.get(acc, 0) + 15
                patterns.setdefault(acc, []).append("high_velocity")

    return suspicious, patterns


def generate_ring_id(index):
    return f"RING_{index:03d}"


# -------------------------------
# Main App
# -------------------------------

st.set_page_config(page_title="Money Muling Detection Engine", layout="wide")

st.title("💸 Money Muling Detection Engine (Graph Based)")
st.write("Upload transaction CSV to detect fraud rings using graph theory.")

uploaded_file = st.file_uploader("Upload CSV File", type=["csv"])

if uploaded_file is not None:
    start_time = time.time()

    df = pd.read_csv(uploaded_file)

    # Validate Columns
    required_cols = ["transaction_id", "sender_id", "receiver_id", "amount", "timestamp"]
    if not all(col in df.columns for col in required_cols):
        st.error("CSV columns mismatch. Required: transaction_id, sender_id, receiver_id, amount, timestamp")
        st.stop()

    # Build Graph
    G = build_graph(df)

    # Detect Cycles
    cycles = detect_cycles(G)
    cycle_suspicious = {}
    cycle_patterns = {}

    for cycle in cycles:
        cycle_len = len(cycle)
        for acc in cycle:
            cycle_suspicious[acc] = cycle_suspicious.get(acc, 0) + 40
            cycle_patterns.setdefault(acc, []).append(f"cycle_length_{cycle_len}")

    # Detect Fan-in/Fan-out
    smurf_scores, smurf_patterns = detect_fan_in_out(df)

    # Detect Shell Chains
    shell_scores, shell_patterns, shell_rings = detect_shell_chains(G)

    # Detect High Velocity
    velocity_scores, velocity_patterns = compute_velocity_scores(df)

    # Merge all suspicious scores and patterns
    suspicion_scores = {}
    detected_patterns = {}

    def merge_scores(scores_dict, patterns_dict):
        for acc, score in scores_dict.items():
            suspicion_scores[acc] = suspicion_scores.get(acc, 0) + score
        for acc, pats in patterns_dict.items():
            detected_patterns.setdefault(acc, []).extend(pats)

    merge_scores(cycle_suspicious, cycle_patterns)
    merge_scores(smurf_scores, smurf_patterns)
    merge_scores(shell_scores, shell_patterns)
    merge_scores(velocity_scores, velocity_patterns)

    # Cap score at 100
    for acc in suspicion_scores:
        suspicion_scores[acc] = min(100, float(suspicion_scores[acc]))

    # -------------------------------
    # Create Fraud Rings
    # -------------------------------
    fraud_rings = []
    suspicious_accounts_output = []

    ring_counter = 1
    ring_map = {}

    # Rings from cycles
    for cycle in cycles:
        ring_id = generate_ring_id(ring_counter)
        ring_counter += 1

        member_accounts = sorted(cycle)
        risk_score = min(100, 70 + len(member_accounts) * 5)

        fraud_rings.append({
            "ring_id": ring_id,
            "member_accounts": member_accounts,
            "pattern_type": "cycle",
            "risk_score": float(risk_score)
        })

        for acc in member_accounts:
            ring_map[acc] = ring_id

    # Rings from shell paths
    for path in shell_rings[:5]:
        ring_id = generate_ring_id(ring_counter)
        ring_counter += 1

        member_accounts = sorted(list(set(path)))
        risk_score = min(100, 60 + len(member_accounts) * 6)

        fraud_rings.append({
            "ring_id": ring_id,
            "member_accounts": member_accounts,
            "pattern_type": "shell_chain",
            "risk_score": float(risk_score)
        })

        for acc in member_accounts:
            if acc not in ring_map:
                ring_map[acc] = ring_id

    # Suspicious accounts list
    for acc, score in suspicion_scores.items():
        suspicious_accounts_output.append({
            "account_id": acc,
            "suspicion_score": float(score),
            "detected_patterns": sorted(list(set(detected_patterns.get(acc, [])))),
            "ring_id": ring_map.get(acc, "NONE")
        })

    suspicious_accounts_output.sort(key=lambda x: x["suspicion_score"], reverse=True)

    processing_time = round(time.time() - start_time, 2)

    # Summary
    summary = {
        "total_accounts_analyzed": int(len(G.nodes())),
        "suspicious_accounts_flagged": int(len(suspicious_accounts_output)),
        "fraud_rings_detected": int(len(fraud_rings)),
        "processing_time_seconds": float(processing_time)
    }

    output_json = {
        "suspicious_accounts": suspicious_accounts_output,
        "fraud_rings": fraud_rings,
        "summary": summary
    }

    # -------------------------------
    # UI OUTPUT
    # -------------------------------

    col1, col2 = st.columns([2, 1])

    with col1:
        st.subheader("📌 Interactive Graph Visualization")

        net = Network(height="600px", width="100%", directed=True, bgcolor="#0f172a", font_color="white")

        for node in G.nodes():
            if node in suspicion_scores:
                net.add_node(node, label=node, color="red", size=25)
            else:
                net.add_node(node, label=node, color="lightblue", size=15)

        for u, v, data in G.edges(data=True):
            net.add_edge(u, v, title=f"Amount: {data['amount']}")

        tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".html")
        net.save_graph(tmp_file.name)

        with open(tmp_file.name, "r", encoding="utf-8") as f:
            html_content = f.read()

        st.components.v1.html(html_content, height=650, scrolling=True)

    with col2:
        st.subheader("📥 Download JSON Output")

        st.download_button(
            label="Download Output JSON",
            data=json.dumps(output_json, indent=2),
            file_name="money_muling_output.json",
            mime="application/json"
        )

        st.subheader("📊 Summary")
        st.json(summary)

    st.subheader("📌 Fraud Ring Summary Table")

    ring_table = []
    for ring in fraud_rings:
        ring_table.append({
            "Ring ID": ring["ring_id"],
            "Pattern Type": ring["pattern_type"],
            "Member Count": len(ring["member_accounts"]),
            "Risk Score": ring["risk_score"],
            "Member Account IDs": ", ".join(ring["member_accounts"])
        })

    ring_df = pd.DataFrame(ring_table)
    st.dataframe(ring_df, use_container_width=True)

    st.subheader("🚨 Suspicious Accounts (Top 20)")
    st.dataframe(pd.DataFrame(suspicious_accounts_output[:20]), use_container_width=True)
streamlit run app.py
