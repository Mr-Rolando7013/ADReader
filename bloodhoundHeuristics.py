import json
from collections import defaultdict, deque

computers_file = 'bloodhound/20260407101035_computers.json'
containers_file = 'bloodhound/20260407101035_containers.json'
domains_file = 'bloodhound/20260407101035_domains.json'
gpos_file = 'bloodhound/20260407101035_gpos.json'
groups_file = 'bloodhound/20260407101035_groups.json'
ous_file = 'bloodhound/20260407101035_ous.json'
users_file = 'bloodhound/20260407101035_users.json'

TIER0_GROUPS = ["DOMAIN ADMINS", "ENTERPRISE ADMINS", "ADMINISTRATORS"]
TIER1_GROUPS = [
    "ACCOUNT OPERATORS",
    "BACKUP OPERATORS",
    "SERVER OPERATORS",
    "PRINT OPERATORS"
]

def loadSIDs(json_computers_file, json_containers_file,
             json_domains_file, json_gpos_file,
             json_groups_file, json_ous_file, json_users_file):
    outputFile = "sids.json"
    
    #Computers
    with open(json_computers_file, 'r') as f:
        data = json.load(f)
    
    computer_output = []

    for obj in data.get("data", []):
        sid = obj.get("ObjectIdentifier")
        property = obj.get("Properties", {})
        name = property.get("name")

        computer_output.append({
            'sid': sid,
            'name': name
        })

    # Containers
    with open(json_containers_file, 'r') as f:
        data = json.load(f)
    
    container_output = []

    for obj in data.get("data", []):
        sid = obj.get("ObjectIdentifier")
        property = obj.get("Properties", {})
        name = property.get("name")

        container_output.append({
            'sid': sid,
            'name': name
        })

    # Domains
    with open(json_domains_file, 'r') as f:
        data = json.load(f)
    
    domains_output = []

    for obj in data.get("data", []):
        sid = obj.get("ObjectIdentifier")
        property = obj.get("Properties", {})
        name = property.get("name")

        domains_output.append({
            'sid': sid,
            'name': name
        })

    # GPOS
    with open(json_gpos_file, 'r') as f:
        data = json.load(f)
    
    gpos_output = []

    for obj in data.get("data", []):
        sid = obj.get("ObjectIdentifier")
        property = obj.get("Properties", {})
        name = property.get("name")

        gpos_output.append({
            'sid': sid,
            'name': name
        })

    # Groups
    with open(json_groups_file, 'r') as f:
        data = json.load(f)
    
    groups_output = []

    for obj in data.get("data", []):
        sid = obj.get("ObjectIdentifier")
        property = obj.get("Properties", {})
        name = property.get("name")

        groups_output.append({
            'sid': sid,
            'name': name
        })

    # OUs
    with open(json_ous_file, 'r') as f:
        data = json.load(f)
    
    ous_output = []

    for obj in data.get("data", []):
        sid = obj.get("ObjectIdentifier")
        property = obj.get("Properties", {})
        name = property.get("name")

        ous_output.append({
            'sid': sid,
            'name': name
        })

    # Users
    with open(json_users_file, 'r') as f:
        data = json.load(f)
    
    users_output = []

    for obj in data.get("data", []):
        sid = obj.get("ObjectIdentifier")
        property = obj.get("Properties", {})
        name = property.get("name")

        users_output.append({
            'sid': sid,
            'name': name
        })

    merged_output = {
        "computers": computer_output,
        "containers": container_output,
        "domains": domains_output,
        "gpos": gpos_output,
        "groups": groups_output,
        "ous": ous_output,
        "users": users_output
    }

    with open(outputFile, 'w') as f:
        json.dump(merged_output, f, indent=2)

def retrieveNameFromSid(sid):
    sid_file = "sids.json"
    if sid == "":
        return ""

    with open(sid_file, 'r') as f:
        data = json.load(f)

    computers = data["computers"]
    for computer in computers:
        if computer["sid"] == sid:
            return computer["name"]
        
    containers = data["containers"]
    for container in containers:
        if container["sid"] == sid:
            return container["name"]
        
    domains = data["domains"]
    for domain in domains:
        if domain["sid"] == sid:
            return domain["name"]
        
    gpos = data["gpos"]
    for gpo in gpos:
        if gpo["sid"] == sid:
            return gpo["name"]
        
    groups = data["groups"]
    for group in groups:
        if group["sid"] == sid:
            return group["name"]
        
    ous = data["ous"]
    for ou in ous:
        if ou["sid"] == sid:
            return ou["name"]
    
    users = data["users"]
    for user in users:
        if user["sid"] == sid:
            return user["name"]
        
    return sid


def exportMemberships():
    with open(groups_file, 'r') as f:
        data = json.load(f)
    result = []
    outputFile = "groupMembers.json"

    for group in data.get("data", []):
        property = group.get("Properties", [])
        tempGroup = property.get("name", "").split("@")[0].upper()
        for member in group.get("Members", []):
            tempMember = retrieveNameFromSid(member["ObjectIdentifier"]).split("@")[0].upper()
            tempType = member["ObjectType"]
            result.append({
                "group": tempGroup,
                "member": tempMember,
                "type": tempType
            })

    with open(outputFile, 'w') as f:
        json.dump(result, f, indent=2)

def define_users():
    outputFile = "userClassification.json"
    result = {}

    with open('groupMembers.json', 'r') as f:
        data = json.load(f)

    for value in data:
        if value["type"] == 'User':
            user = value["member"]

            if value["group"] in TIER0_GROUPS:
                score = 2
            elif value["group"] in TIER1_GROUPS:
                score = 1.8
            else:
                score = 1
            if user in result:
                result[user] = max(result[user], score)
            else:
                result[user] = score

    output_list = [
        {"User": user, "Score": score}
        for user, score in result.items()
    ]

    with open(outputFile, 'w') as f:
        json.dump(output_list, f, indent=2)


def get_dc_nodes(nodes):
    return {
        node for node, props in nodes.items()
        if props.get("isDomainController") is True
    }

def build_attack_graph(data, dangerous_privs, permissions_baseline, userClassificationFile):
    reverse_graph = defaultdict(list)
    nodes = {}
    edges = []

    with open(userClassificationFile, 'r') as f:
        user_data = json.load(f)


    for obj in data:
        properties = obj.get("Properties", {})
        target = properties.get("name")

        if not target:
            continue

        target_norm = target.split("@")[0].upper()

        # ensure node exists
        nodes.setdefault(target_norm, {"isDomainController": False})

        # detect domain controller
        if properties.get("primaryGroupID") == 516:
            nodes[target_norm]["isDomainController"] = True

        if "DOMAIN CONTROLLERS" in properties.get("memberOf", []):
            nodes[target_norm]["isDomainController"] = True

        if "DC" in target_norm:
            nodes[target_norm]["isDomainController"] = True

        aces = obj.get("Aces", [])

        for ace in aces:
            right = ace.get("RightName")
            if right not in dangerous_privs:
                continue

            principal = retrieveNameFromSid(ace.get("PrincipalSID", ""))
            if not principal:
                continue

            principal_norm = principal.split("@")[0].upper()

            # Each ACE has a principal, so the principal also becomes a node
            nodes.setdefault(principal_norm, {"isDomainController": False})

            score = permissions_baseline.get(right, 0)

            for obj in user_data:
                if obj["User"] == target_norm:
                    score += obj["Score"]
            

            edge = {
                "from": principal_norm,
                "to": target_norm,
                "type": right,
                "score": score
            }

            edges.append(edge)
            reverse_graph[target_norm].append(principal_norm)

    return edges, reverse_graph, nodes

def bfs_with_paths(sources, reverse_graph, edges):
    # (from, to) -> edge
    edge_lookup = defaultdict(list)
    for e in edges:
        edge_lookup[(e["from"], e["to"])].append(e)

    # Initialize BFS
    # sources = starting node
    # visited[node] = distance
    # parent[node] = how we got there
    queue = deque(sources)
    visited = {s: 0 for s in sources}
    parent = {s: None for s in sources}

    while queue:
        node = queue.popleft()

        for neighbor in reverse_graph.get(node, []):
            # Visit new nodes
            if neighbor not in visited:
                # Record distance
                visited[neighbor] = visited[node] + 1
                # reversed direction
                # Store parent
                edge = edge_lookup.get((neighbor, node))
                parent[neighbor] = {
                    "prev": node,
                    "edge": edge
                }

                queue.append(neighbor)

    return visited, parent

def reconstruct_path_with_edges(node, parent):
    path = []

    while node in parent and parent[node] is not None:
        entry = parent[node]

        edge = entry["edge"]

        # handle list vs dict
        if isinstance(edge, list):
            edge = edge[0] if edge else None

        path.append({
            "node": node,
            "edge_type": edge["type"] if edge else None
        })

        node = entry["prev"]

    path.append({"node": node, "edge_type": None})
    return list(reversed(path))

def score_chain(chain):
    score = 0

    for edge in chain:
        score += edge.get("score", 0)

    score += 5

    return score
