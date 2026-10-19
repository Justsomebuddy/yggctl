"""Standalone offline SVG/HTML atlas; no CDN, geolocation or network access."""

import html as escaping
import json
import math

from core import logged

# Coarse country centres, ONLY to place catalogue claims, not node coordinates.
CENTRES = {
    "armenia": (40, 45),
    "australia": (-25, 134),
    "austria": (47, 14),
    "brazil": (-14, -52),
    "canada": (57, -106),
    "chile": (-33, -71),
    "china": (35, 104),
    "czechia": (50, 15),
    "czech-republic": (50, 15),
    "denmark": (56, 10),
    "estonia": (59, 26),
    "finland": (64, 26),
    "france": (47, 2),
    "germany": (51, 10),
    "greece": (39, 22),
    "hungary": (47, 19),
    "iceland": (65, -19),
    "india": (22, 79),
    "indonesia": (-2, 118),
    "ireland": (53, -8),
    "israel": (31, 35),
    "italy": (42, 13),
    "japan": (36, 138),
    "kazakhstan": (48, 67),
    "latvia": (57, 25),
    "lithuania": (55, 24),
    "luxembourg": (50, 6),
    "mexico": (24, -102),
    "netherlands": (52, 5),
    "new-zealand": (-41, 174),
    "norway": (62, 10),
    "poland": (52, 19),
    "portugal": (40, -8),
    "romania": (46, 25),
    "russia": (61, 100),
    "serbia": (44, 21),
    "singapore": (1, 104),
    "south-africa": (-29, 25),
    "south-korea": (36, 128),
    "spain": (40, -4),
    "sweden": (62, 15),
    "switzerland": (47, 8),
    "taiwan": (24, 121),
    "turkey": (39, 35),
    "ukraine": (49, 32),
    "united-kingdom": (55, -3),
    "united-states": (39, -98),
}


@logged
def geography(data):
    lines = [
        '<svg viewBox="0 0 960 480" role="img" aria-label="Country claims, NOT node geolocation"><rect width="960" height="480" fill="#102437"/>'
    ]
    for longitude in range(-180, 181, 30):
        x = (longitude + 180) / 360 * 960
        lines.append(
            f'<path d="M{x} 0V480" stroke="#294358"/><text x="{x + 2}" y="14" fill="#7f9db2" font-size="10">{longitude}°</text>'
        )
    for latitude in range(-60, 61, 30):
        y = (90 - latitude) / 180 * 480
        lines.append(
            f'<path d="M0 {y}H960" stroke="#294358"/><text x="2" y="{y - 2}" fill="#7f9db2" font-size="10">{latitude}°</text>'
        )
    for country, counts in data["countries"].items():
        if country not in CENTRES:
            continue
        latitude, longitude = CENTRES[country]
        x = (longitude + 180) / 360 * 960
        y = (90 - latitude) / 180 * 480
        radius = min(25, 4 + math.sqrt(counts["endpoints"]))
        label = escaping.escape(
            f"{country}: {counts['endpoints']} endpoint records; {counts['pin_keys']} claimed pin keys. Catalogue geography ONLY."
        )
        lines.append(
            f'<circle cx="{x:.2f}" cy="{y:.2f}" r="{radius:.2f}" fill="#4ad1bc" fill-opacity=".65" stroke="#a5fff1"><title>{label}</title></circle>'
        )
    return "".join(lines + ["</svg>"])


@logged
def html(data):
    # Browser receives only projected/validated keys, enums and country claims.
    # JSON is script-safe even if a future field contains a markup character.
    payload = (
        json.dumps({"nodes": data["nodes"], "edges": data["edges"]}, allow_nan=False)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )
    country_rows = "".join(
        "<tr><td>"
        + escaping.escape(c)
        + "</td><td>"
        + str(v["endpoints"])
        + "</td><td>"
        + str(v["pin_keys"])
        + "</td><td>"
        + str(v["registry_online"])
        + "/"
        + str(v["registry_offline"])
        + "/"
        + str(v["registry_unknown"])
        + "</td></tr>"
        for c, v in data["countries"].items()
    )
    limits = "".join("<li>" + escaping.escape(label) + "</li>" for label in data["limits"])
    missing_centres = ", ".join(c for c in data["countries"] if c not in CENTRES) or "none"
    page = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; base-uri 'none'; form-action 'none'">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Observed Yggdrasil atlas</title>
<style>body{background:#071421;color:#d2e6f2;font:15px system-ui;margin:24px;max-width:1500px}h1,h2{color:#67ddd0}section{background:#102437;border:1px solid #294358;border-radius:12px;padding:18px;margin:18px 0}svg{width:100%;max-height:660px}label{display:inline-block;margin:8px}input,button{background:#071421;color:#d2e6f2;border:1px solid #56788e;padding:8px;border-radius:5px}input[type=text]{width:min(420px,80%)}pre{white-space:pre-wrap;overflow-wrap:anywhere}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #294358;text-align:left;padding:6px}.unknown{color:#ffc56d}circle.node{cursor:pointer}circle.node.selected{stroke:#fff;stroke-width:3}button{cursor:pointer}</style>
<h1>Observed Yggdrasil world atlas</h1><p class="unknown">World size, completeness and capacity: UNKNOWN. This is observed/claimed data, not a global census.</p>
<p>Generated @GENERATED@ · identities/references @NODES@ · valid-payload respondents @RESPONDENTS@ · advertised endpoint records @ENDPOINTS@</p>
<section><h2>Catalogue country / network labels</h2><p>Markers at coarse country centres. Marker size counts advertised endpoint records, NOT nodes. No GeoIP/ASN or exact locations inferred. Labels can include non-geographic networks such as lokinet: they are NOT countries.</p>@GEOGRAPHY@<p>Claims without a display centre: @MISSING@. Not discarded from JSON/table.</p><table><thead><tr><th>Catalogue label</th><th>Endpoint records</th><th>Pin identities</th><th>Registry online/offline/unknown</th></tr></thead><tbody>@COUNTRIES@</tbody></table></section>
<section><h2>Observed topology</h2><p>Green: local direct; orange: remote reported peers; dashed blue: local tree parents. Remote tree keys are references, NOT edges. Ring layout is NOT geography or routing distance.</p>
<label>Key prefix <input id="search" type="text" maxlength="64" placeholder="public key prefix"></label>
<label><input id="reported" type="checkbox" checked>Reported peers</label><label><input id="parents" type="checkbox" checked>Local tree parents</label><button id="reset" type="button">Reset filters</button>
<p id="counts"></p><svg id="graph" viewBox="0 0 1000 700" role="img" aria-label="Observed topology"></svg><pre id="details">Click a vertex. Missing data is unknown, not offline.</pre></section>
<section><h2>Scope / unknown</h2><ul>@LIMITS@</ul><p>Acquisition has no32-node cutoff. Display maximum2000 vertices/10000 edges to bound browser CPU; search uses the complete JSON graph and can display matched vertices plus neighbours. Full data remains in JSON/DOT.</p></section>
<script id="atlas-data" type="application/json">@DATA@</script>
<script>
"use strict";
function trace(label,fn){console.debug("atlas-ui entry",label);try{const result=fn();console.debug("atlas-ui exit",label);return result;}catch(error){console.error("atlas-ui error",label,error.name);throw error;}}
const data=JSON.parse(document.getElementById("atlas-data").textContent);
const byKey=new Map();for(const n of data.nodes){byKey.set(n.key,n);}
function element(tag,attrs){return trace("element",()=>{const e=document.createElementNS("http://www.w3.org/2000/svg",tag);for(const k of Object.keys(attrs)){e.setAttribute(k,attrs[k]);}return e;});}
function select(key){return trace("select",()=>{document.getElementById("details").textContent=JSON.stringify(byKey.get(key),null,2);for(const e of document.querySelectorAll("circle.node")){e.classList.toggle("selected",e.dataset.key===key);}console.debug("atlas-ui state","vertex-selected");});}
function render(){return trace("render",()=>{
const prefix=document.getElementById("search").value.trim().toLowerCase();const keys=new Set();
for(const n of data.nodes){if(!prefix||n.key.startsWith(prefix)){keys.add(n.key);}}
if(prefix){for(const e of data.edges){if(keys.has(e.source)&&e.source.startsWith(prefix)){keys.add(e.target);}if(keys.has(e.target)&&e.target.startsWith(prefix)){keys.add(e.source);}}}
const shown=[];if(prefix){for(const n of data.nodes){if(n.key.startsWith(prefix)&&shown.length<2000){shown.push(n);}}}
for(const n of data.nodes){if(keys.has(n.key)&&(!prefix||!n.key.startsWith(prefix))&&shown.length<2000){shown.push(n);}}
const positions=new Map();for(let i=0;i<shown.length;i++){const angle=2*Math.PI*i/Math.max(1,shown.length);positions.set(shown[i].key,[500+305*Math.cos(angle),350+305*Math.sin(angle)]);}
const graph=document.getElementById("graph");graph.replaceChildren();let count=0;
for(const e of data.edges){if(!positions.has(e.source)||!positions.has(e.target)||count>=10000){continue;}if(e.kind==="reported_peer"&&!document.getElementById("reported").checked){continue;}if(e.kind==="local_tree_parent"&&!document.getElementById("parents").checked){continue;}
const a=positions.get(e.source),b=positions.get(e.target);const line=element("line",{x1:a[0],y1:a[1],x2:b[0],y2:b[1],stroke:e.kind==="reported_peer"?"#db9950":e.kind==="local_tree_parent"?"#658fbd":"#4ad1bc","stroke-opacity":".22"});if(e.kind==="local_tree_parent"){line.setAttribute("stroke-dasharray","5 5");}graph.append(line);count++;}
for(const n of shown){const p=positions.get(n.key);const circle=element("circle",{cx:p[0],cy:p[1],r:Math.min(9,3+Math.sqrt(n.observed_peer_degree)/2),fill:n.roles.includes("validated_payload_respondent")?"#4ad1bc":"#8e9dad",class:"node"});circle.dataset.key=n.key;const title=element("title",{});title.textContent=n.key+" · observed degree "+n.observed_peer_degree;circle.append(title);circle.addEventListener("click",()=>trace("click",()=>select(n.key)));graph.append(circle);}
document.getElementById("counts").textContent="Displayed "+shown.length+"/"+data.nodes.length+" vertices and "+count+"/"+data.edges.length+" relations; omissions are display-only. Full world coverage UNKNOWN.";console.debug("atlas-ui state","graph-rendered");});}
document.getElementById("search").addEventListener("input",()=>trace("search-input",()=>render()));
for(const id of ["reported","parents"]){document.getElementById(id).addEventListener("change",()=>trace("layer-change",()=>render()));}
document.getElementById("reset").addEventListener("click",()=>trace("reset",()=>{document.getElementById("search").value="";document.getElementById("reported").checked=true;document.getElementById("parents").checked=true;render();}));
render();
</script></html>"""
    for key, value in {
        "GENERATED": escaping.escape(data["generated"]),
        "NODES": str(len(data["nodes"])),
        "RESPONDENTS": str(data["respondent_keys"]),
        "ENDPOINTS": str(len(data["catalogue"])),
        "GEOGRAPHY": geography(data),
        "MISSING": escaping.escape(missing_centres),
        "COUNTRIES": country_rows,
        "LIMITS": limits,
        "DATA": payload,
    }.items():
        page = page.replace("@" + key + "@", value)
    return page
