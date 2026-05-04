from bloodhoundHeuristics import *

def main():

    TIER0_GROUPS = ["DOMAIN ADMINS", "ENTERPRISE ADMINS", "ADMINISTRATORS"]
    TIER1_GROUPS = [
        "ACCOUNT OPERATORS",
        "BACKUP OPERATORS",
        "SERVER OPERATORS",
        "PRINT OPERATORS"
    ]

    dangerousPrivs = [
        "GenericAll", "GenericWrite", "WriteProperty", "WriteSPN",
        "Validated-SPN", "Self", "AllExtendedRights", "Self-Membership",
        "User-Force-Change-Password", "ForceChangePassword",
        "ReadLAPSPassword", "ReadGMSAPassword", "Owns", "WriteDacl",
        "AddMember", "WriteOwner"
    ]

    permissions_baseline = {
        "GenericAll": 2.5,
        "GenericWrite": 2.0,
        "WriteDacl": 1.8,
        "WriteSPN": 2.2
    }

    files = [
        computers_file,
        containers_file,
        users_file,
        ous_file,
        groups_file,
        gpos_file,
        domains_file
    ]

    # Load data
    data = []
    for file in files:
        with open(file, "r") as f:
            content = json.load(f)
            data.extend(content.get("data", []))

    # Build graph
    edges, reverse_graph, nodes = build_attack_graph(
        data,
        dangerousPrivs,
        permissions_baseline,
        "userClassification.json"
    )

    dc_nodes = get_dc_nodes(nodes)
    distances, parent = bfs_with_paths(dc_nodes, reverse_graph, edges)

    hops_baseline = {
        1: 2.5,
        2: 1.8,
        3: 1.2
    }

    TIER0_GROUPS = set(TIER0_GROUPS)

    # Score and classify edges
    for edge in edges:
        node = edge["from"]

        # default
        edge["is_interesting"] = False

        # If it is already domain admin, skip
        if node in TIER0_GROUPS:
            continue

        # mark interesting if dangerous privilege
        if edge["type"] in dangerousPrivs:
            edge["is_interesting"] = True

        # hop-based scoring
        hops = distances.get(node)
        if hops is not None:
            hop_weight = hops_baseline.get(hops, 0)
            edge["score"] = edge.get("score", 0) * hop_weight

    for node, hops in distances.items():
        path = reconstruct_path_with_edges(node, parent)

        formatted = []
        for step in path:
            if step["edge_type"]:
                formatted.append(f"--[{step['edge_type']}]--> {step['node']}")
            else:
                formatted.append(step["node"])

        print(f"{node}: {hops} hops -> " + " ".join(formatted))

    print("Max hops:", max(distances.values()))

    # Filter edges for chaining
    filtered_edges = [
        e for e in edges
        if e.get("is_interesting")
        and e["from"] not in TIER0_GROUPS
    ]

    # Build adjacency graph
    graph = {}
    for edge in filtered_edges:
        graph.setdefault(edge["from"], []).append(edge)

    # Build 2-hop chains
    chains = []

    for edge1 in filtered_edges:
        mid = edge1["to"]

        for edge2 in graph.get(mid, []):
            if edge2["from"] in TIER0_GROUPS:
                continue

            chains.append([edge1, edge2])

    # Chain scoring
    def score_chain(chain):
        score = sum(e.get("score", 0) for e in chain)

        # reward chaining (pivot potential)
        score += 4

        # service account bonus (This can be deleted)
        if any(".SVC" in e["to"] for e in chain):
            score += 3

        # penalize Tier 0 involvement
        if any(e["from"] in TIER0_GROUPS for e in chain):
            score -= 10

        return score

    # Rank chains
    ranked_chains = sorted(
        chains,
        key=score_chain,
        reverse=True
    )

    # Output top chains
    for chain in ranked_chains[:5]:
        print("\nCHAIN:")
        for e in chain:
            print(f"  {e['from']} --[{e['type']}]--> {e['to']}")

    print("Edges: ", edges)

if __name__ == '__main__':
    main()