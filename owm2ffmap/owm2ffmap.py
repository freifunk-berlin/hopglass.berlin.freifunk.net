import datetime
import dateutil.parser
import json
import re
import traceback
import sys
from tornado import gen, ioloop, httpclient
from diskcache import Cache

# This is a quick hack to pull Freifunk node data for a specific geographic area
# from OpenWifiMap (OWM) and to convert it to the format used by Gluon communities
# typically (ffmap-backend, nodes.json and graph.json) in order to be able to use
# it with compatible frontends such as HopGlass.

# The cache is mostly helpful when debugging the script.
# Use /dev/shm ramdisk since that's much faster than real disks on shared VMs
# typically.
cache = Cache('/dev/shm/owm2ffmap_cache')
i = 0

def handle_request(response):
    global i
    print "URL: %s, code: %d, bytes: %d, URLs to go: %d" % (response.effective_url, response.code, len(response.body) if response.code == 200 else 0, i)
    if response.code == 200:
        cache.set(response.effective_url, response.body, expire=60*30)
        process_node_json(response.effective_url, response.body)
    elif response.code == 599:
        print "Timeout for %s, re-queuing" % response.effective_url
        http_client.fetch(response.effective_url, handle_request, method='GET')
        i += 1
    i -= 1
    if i == 0:
        ioloop.IOLoop.instance().stop()

def get_nodes():
    global cache
    url = "http://api.openwifimap.net/view_nodes_spatial?bbox=12.9,52.27,13.8,52.7"  # Berlin
    if url in cache:
        return cache[url]
    http_client = httpclient.HTTPClient()
    response = http_client.fetch(url)
    http_client.close()
    body = response.body
    cache.set(url, body, expire=60*10)
    return body

# extracts firmware-data from OWM-data and returns name and revision
def parse_firmware(firmware):
        try:
            if "name" in firmware and len(firmware["name"])>0:
                firmware_base = firmware["name"]  # Kathleen >= 0.2.0 uses "name" field
            else:
                firmware_base = firmware["revision"]  # "Freifunk Berlin kathleen 0.2.0-beta+718cff0"
            firmware_base = re.sub(r'^Freifunk-Berlin', 'Freifunk Berlin', firmware_base)
            firmware_base = re.sub(r'^Freifunk Berlin kathleen', 'Kathleen', firmware_base) # "Kathleen 0.2.0-beta+718cff0"
            firmware_base = re.sub(r'^OpenWrt Attitude Adjustment', 'OpenWrt AA', firmware_base)
            firmware_base = re.sub(r'^OpenWrt Barrier Breaker', 'OpenWrt BB', firmware_base)
            firmware_base = re.sub(r'^OpenWrt Chaos Calmer', 'OpenWrt CC', firmware_base)
            firmware_release = re.sub(r'\+[a-f0-9]{7}$', '', firmware_base)  # "Kathleen 0.2.0-beta"
        except:
            firmware_base = "unknown"
            firmware_release = "unknown"
    return(firmware_base, firmware_release)

nodes = []
graphnodes = dict()
graphlinks = []

def process_node_json(url, body):
    global nodes
    global graphnodes
    global graphlinks
    try:
        print "Converting " + url
        owmnode = json.loads(body)
        firstseen = owmnode["ctime"][:-1]
        lastseen = owmnode["mtime"][:-1]
        lastseensecs = (datetime.datetime.utcnow() - dateutil.parser.parse(lastseen)).total_seconds()
        isonline = lastseensecs < 60*60*24  # assume offline if not seen for more than a day
        if lastseensecs > 60*60*24*7:
            print "...offline more than a week, skipping"
            return
        isuplink = len([a for a in owmnode.get("interfaces", []) if a.get("ifname", "none") == "ffvpn"]) > 0
        hasclientdhcp = len([a for a in owmnode.get("interfaces", [])
                             if(a.get("encryption", "unknown") == "none" and a.get("mode", "unknown") == "ap")
                               or a.get("ifname", "none") == "br-dhcp"
                            ]) > 0
        site_code = "hotspot" if hasclientdhcp else "routeronly"  # hack: allow selecting nodes with hotspot functionality via statistics
        try:
            uptimesecs = owmnode["system"]["uptime"][0]
        except:
            uptimesecs = 0
        hostid = owmnode["_id"]  # with ".olsr"
        hostname = owmnode["hostname"]  # without ".olsr"
        is24ghz = True
        try:
            for interface in owmnode["interfaces"]:
                if "channel" in interface:
                    if int(interface["channel"]) > 15:
                        is24ghz = False
        except:
            pass
        try:
            chipset = owmnode.get("hardware", "unknown").strip()
        except:
            chipset = "unknown"
        try:
            hardware_model = owmnode["system"]["sysinfo"][1].strip()
            if hardware_model.startswith(("Ubiquiti Nanostation M", "Ubiquiti Bullet M", "Ubiquiti Rocket M")):
                # For Ubiquiti routers, add 2.4GHz/5GHz indication
                hardware_model = hardware_model.replace(' M', " M2" if is24ghz else " M5")
        except:
            hardware_model = "unknown"
        try:
            email = owmnode["freifunk"]["contact"].get("mail", "")
        except:
            email = ""
        longitude = owmnode["longitude"]
        latitude = owmnode["latitude"]
        (firmware_base, firmware_release) = parse_firmware(owmnode["firmware"])

        node = {'firstseen': firstseen,
                'flags': {'online': isonline, 'uplink': isuplink},
                'lastseen': lastseen,
                'nodeinfo': {
                    'hardware': {'model': hardware_model,
                                 'nproc': 1},  # TODO
                    'hostname': hostname,
                    'location': {'latitude': latitude, 'longitude': longitude},
                    #'network': {'addresses': False, #TODO
                    #            'mac': False, #TODO
                    #            'mesh': False}, #TODO
                    'node_id': hostid,
                    'owner': {'contact': email},
                    'software': {'firmware': {'base': firmware_base, 'release': firmware_release}},
                    'system': {'role': 'node', 'site_code': site_code}
                },
                'statistics': {
                    'clients': 0,  # we don't want client statistics
                    'uptime': uptimesecs
                }
               }
        nodes.append(node)
        print node

        for link in owmnode.get("links", []):
          targetid = link["id"]
          quality = link["quality"]
          quality = 1.0/float(quality) if quality > 0 else 999
          graphlink = {'bidirect': True,
                       'source': hostid,
                       'target': targetid,
                       'tq': quality,
                       'vpn': False}
          graphlinks.append(graphlink)
          print graphlink
        graphnodes[hostid] = {"id": hostid, "node_id": hostid, "seq": len(graphnodes)}
        print graphnodes[hostid]
        print "**********************************"
    except:
        traceback.print_exc(file=sys.stdout)







data = json.loads(get_nodes())

timestamp = datetime.datetime.utcnow().isoformat()

http_client = httpclient.AsyncHTTPClient()
for row in data["rows"]:
    url = "http://api.openwifimap.net/db/" + row["id"].strip()
    nodejson = cache.get(url, None)
    if nodejson is None:
        i += 1
        http_client.fetch(url, handle_request, method='GET')  # calls process_node_json internally
    else:
        process_node_json(url, nodejson)

print "Getting %d node infos" % i
if i > 0:
    ioloop.IOLoop.instance().start()

# node data has been fetched and converted here

# fixup links in graph.json
brokenlinks = []
for link in graphlinks:
  try:
    link["source"] = graphnodes[link["source"]]["seq"]
    link["target"] = graphnodes[link["target"]]["seq"]
  except:
    print "Could not resolve source %s or target %s for graph" % (link["source"], link["target"])
    brokenlinks.append(link)
graphlinks = [link for link in graphlinks if link not in brokenlinks]

graphnodes = [node for _, node in graphnodes.iteritems()]
graphnodes = sorted(graphnodes, key=lambda x: x["seq"])
graph = {"batadv": {"directed": False, "graph": [], "links": graphlinks, "multigraph": False, "nodes": graphnodes}, "version": 1}
print graph
with open("graph.json", "w") as outfile:
    json.dump(graph, outfile)

# finalize nodes.json
nodes = {"nodes": nodes, "timestamp": timestamp, "version": 2}
print nodes
with open("nodes.json", "w") as outfile:
    json.dump(nodes, outfile)

print "Wrote %d nodes." % len(nodes["nodes"])

cache.close()
