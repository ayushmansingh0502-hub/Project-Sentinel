"""Quick integration test for the full SwarmSentinel pipeline."""
import os
import requests
import time

BASE = "http://127.0.0.1:8000"
API_KEY = (os.getenv("API_KEY") or "").strip()
if not API_KEY:
    raise RuntimeError("API_KEY environment variable is required.")

H = {"x-api-key": API_KEY, "Content-Type": "application/json"}
H_GET = {"x-api-key": API_KEY}

# Run APT killchain scenario
r = requests.post(f"{BASE}/swarm/simulate", headers=H, json={
    "action": "scenario",
    "scenario": "apt_killchain",
    "events_per_second": 5.0,
})
print("Simulation:", r.json())

# Wait for it to complete
time.sleep(6)

# Check graph
r = requests.get(f"{BASE}/swarm/graph", headers=H_GET)
stats = r.json()["stats"]
print(f"Graph: {stats['node_count']} nodes, {stats['edge_count']} edges, pheromone={stats['total_pheromone']:.1f}")

# Check hotspots
r = requests.get(f"{BASE}/swarm/hotspots?top_n=5", headers=H_GET)
hotspots = r.json()["hotspots"]
print(f"Hotspots: {len(hotspots)}")
for h in hotspots[:3]:
    print(f"  {h['entity_id']}: pheromone={h['total_pheromone']:.1f}")

# Check incidents
r = requests.get(f"{BASE}/incidents", headers=H_GET)
incidents = r.json()["incidents"]
print(f"Incidents: {len(incidents)}")
for inc in incidents[:3]:
    entities = ", ".join(f"{e['type']}:{e['id']}" for e in inc.get("entities", []))
    mitre = inc.get("mitre", [])
    print(f"  INC-{inc['id']}: score={inc['score']:.1f} mitre={mitre} entities=[{entities}]")

# Check corridors
r = requests.get(f"{BASE}/swarm/corridors?min_strength=0.5", headers=H_GET)
corridors = r.json()["corridors"]
print(f"Attack corridors: {len(corridors)}")
for c in corridors[:3]:
    print(f"  {c['source']} -> {c['target']}: weight={c['weight']:.2f}")

print("\n=== Full pipeline test PASSED ===")
