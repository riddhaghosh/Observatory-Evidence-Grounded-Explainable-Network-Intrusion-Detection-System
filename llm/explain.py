import os
import json
from dotenv import load_dotenv
from groq import Groq

load_dotenv(override=True)  # force .env values to take priority over any existing OS-level env vars

MODEL_NAME = "openai/gpt-oss-20b"

client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

from rag.retrieve import retrieve


def build_retrieval_query(evidence):
    """
    Build a retrieval query from whatever fields are actually present in
    this alert's evidence, instead of relying on each caller to supply a
    fixed string. This keeps retrieval aligned with what was actually
    detected -- a scan alert pulls scan-shaped knowledge, a brute-force
    alert pulls brute-force-shaped knowledge -- instead of always
    retrieving the same generic chunks regardless of attack type.
    """
    detection_type = evidence.get("detection_type") or evidence.get("prediction", "network attack")
    parts = [str(detection_type)]

    # Aggregate-rule-specific signals (scan/bruteforce/dos detectors)
    if "distinct_ports_contacted" in evidence:
        parts.append(f"{evidence['distinct_ports_contacted']} distinct destination ports contacted short time port scan")
    if "attempts_in_window" in evidence:
        parts.append(f"{evidence['attempts_in_window']} repeated connection attempts same port login brute force")
    if "flow_count_in_window" in evidence:
        parts.append(f"{evidence['flow_count_in_window']} flows high volume flood denial of service")

    # Per-flow ML evidence signals
    if "destination_port" in evidence:
        parts.append(f"port {evidence['destination_port']}")
    if evidence.get("flow_packets_per_sec", 0) and evidence["flow_packets_per_sec"] > 1000:
        parts.append("high packet rate short duration")
    if evidence.get("syn_flag_count", 0):
        parts.append("SYN flag")
    if evidence.get("fin_flag_count", 0):
        parts.append("FIN flag")

    return " ".join(parts)


def build_prompt(evidence, retrieved_chunks):
    evidence_str = json.dumps(evidence, indent=2)

    context_str = "\n\n".join([
        f"[Source: {c['source_file']}]\n{c['text']}"
        for c in retrieved_chunks
    ])

    prompt = f"""You are a network security analyst assistant. Analyze the 
detected network event using ONLY the evidence and retrieved documents 
below. Do not invent information that isn't supported by them.

DETECTION EVIDENCE:
{evidence_str}

RETRIEVED CYBERSECURITY KNOWLEDGE:
{context_str}

Only reference fields that are actually present in the DETECTION EVIDENCE 
above. Do not assume fields like source IP, destination IP, or Flow ID 
exist unless they explicitly appear in the evidence JSON. If information 
like that would normally be useful but is not available in the evidence, 
say so explicitly (e.g. "source IP is not available in this evidence; 
investigate the host associated with this flow via other logs") instead 
of assuming it exists.

If the RETRIEVED CYBERSECURITY KNOWLEDGE above does not explicitly name a 
MITRE ATT&CK technique ID relevant to this evidence, you MUST say so 
plainly (e.g. "no specific MITRE ATT&CK technique identified in the 
retrieved knowledge for this evidence") rather than stating a technique 
ID from memory or guessing one you are not confident is correct. Never 
state a technique ID (e.g. "T1110", "T1046") unless that exact ID appears 
in the RETRIEVED CYBERSECURITY KNOWLEDGE text above.

Based strictly on the evidence and retrieved knowledge above, provide:
1. What likely happened (attack type)
2. Why it was detected (cite specific evidence fields)
3. The relevant MITRE ATT&CK technique, if supported by the retrieved 
   documents
4. Recommended investigation steps

If the evidence is insufficient to support a confident conclusion, say so 
explicitly rather than guessing."""

    return prompt


def get_explanation(evidence, top_k=3):
    query = build_retrieval_query(evidence)
    retrieved_chunks = retrieve(query, top_k=top_k)

    prompt = build_prompt(evidence, retrieved_chunks)

    response = client.chat.completions.create(
        model=MODEL_NAME,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.3,
        max_tokens=2500,
    )

    return response.choices[0].message.content


if __name__ == "__main__":
    sample_evidence = {
        "row_index": 6864,
        "prediction": "ATTACK",
        "confidence": 0.9778,
        "destination_port": 21,
        "flow_duration": 49.0,
        "flow_bytes_per_sec": 489795.9184,
        "flow_packets_per_sec": 81632.65306,
        "syn_flag_count": 0,
        "fin_flag_count": 0,
        "top_contributing_features": ["Bwd Packet Length Std", "Average Packet Size"]
    }

    print(f"Retrieval query: {build_retrieval_query(sample_evidence)}\n")
    print("Generating explanation...\n")
    explanation = get_explanation(sample_evidence)
    print(explanation)