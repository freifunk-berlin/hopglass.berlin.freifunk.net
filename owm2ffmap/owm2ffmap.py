import datetime
import dateutil.parser
import json
from glob import glob
import os
import re
import traceback
import sys
from tornado import gen, ioloop, httpclient
from tornado.escape import url_unescape, url_escape
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

firmware_prekathleen = re.compile("^Freifunk Berlin [0-9]\.*")
firmware_hedy = re.compile("^Freifunk Berlin [hH]edy 1\.[0-9]\.[0-9]")
firmware_falter = re.compile("^Freifunk Falter [0-9]\.[0-9]\.[0-9]")
firmware_ffb_dev = re.compile("^Freifunk Berlin Dev")
firmware_potsdam = re.compile("^Freifunk Potsdam")
firmware_kathleen_correct = re.compile("^Freifunk Berlin kathleen 0\.[2-3]\.0$")
firmware_kathleen_correct_dev = re.compile("^Freifunk[ -]Berlin [kK]athleen 0\.[2-3]\.0-.*\+[a-f0-9]{7}$")
firmware_pre020  = re.compile("^Freifunk Berlin kathleen 0\.[0-1]\.[0-2]$")
firmware_pre020_dev  = re.compile("^Freifunk[ -]Berlin kathleen 0\.[0-2]\.[0-2][ -].*")
firmware_kathleen1505 = re.compile("^Freifunk Berlin kathleen 15.05(\.1){0,1}$")
firmware_openwrt = re.compile("^OpenWrt .*")

bounding_box = "12.9,52.27,14.12,52.7"  # Berlin and parts of East Brandenburg (-> Fuerstenwalde)
bounding_box_elems = [float(x) for x in bounding_box.split(",")]

update_tests = "".join(sys.argv[1:]) == "--update-tests"


def fw_version_equal_or_more_recent(ver_a, ver_b: str, ) -> bool:
    """Returns True if ver_a is a semantic version string and greater
    or equal to ver_b, otherwise False."""
    va_re = re.search(".*([0-9]+\.[0-9]+\.[0-9]*)", ver_a)
    if not va_re:
        return False
    va = [int(n) for n in va_re.group(1).split(".")]
    vb = [int(n) for n in ver_b.split(".")]
    for i in range(0, 3):
        if va[i] != vb[i]:
            return va[i] > vb[i]
    return True


def handle_request(response):
    """requests node data using the asynchronous http client of tornado module."""
    global i
    print("URL: %s, code: %d, bytes: %d, URLs to go: %d" % (response.effective_url, response.code, len(response.body) if response.code == 200 else 0, i))
    if response.code == 200:
        cache.set(response.effective_url, response.body, expire=60*30)
        process_node_json(response.effective_url, response.body)
    elif response.code == 599:
        print("Timeout for %s, re-queuing" % response.effective_url)
        http_client.fetch(response.effective_url, handle_request, method='GET')
        i += 1
    i -= 1
    if i == 0:
        ioloop.IOLoop.instance().stop()

def get_nodes():
    """gets a list of all routers within the bounding box from openwifimap"""
    global cache
    url = "https://api.openwifimap.net/view_nodes_spatial?bbox=" + bounding_box
    if url in cache:
        return cache[url]
    http_client = httpclient.HTTPClient()
    response = http_client.fetch(url)
    http_client.close()
    body = response.body
    cache.set(url, body, expire=60*10)
    return body

def check_location(lonE, latN):
    """excludes all routers outside the boundary box from processing"""
    if not bounding_box_elems[0] < float(lonE) < bounding_box_elems[2]:
        return False
    if not bounding_box_elems[1] < float(latN) < bounding_box_elems[3]:
        return False
    return True

def parse_firmware(firmware):
        """extracts firmware data from OWM data and returns firmware name and revision"""
        firmware_base = "unknown"
        firmware_release = "unknown"
        print("Firmware (raw): %s/%s" % (firmware['name'], firmware['revision']))
        try:
            if "name" in firmware and len(firmware["name"])==0:
                firmware_name = firmware["revision"]  # Kathleen < 0.2.0 uses "revision" field for all data
                if firmware_pre020.match(firmware_name):
                    print("Kathleen pre-0.2.0")
                    firmware_release = firmware_name
                    firmware_base = re.sub(r'^Freifunk Berlin kathleen ', 'v', firmware_name)
                elif firmware_pre020_dev.match(firmware_name):
                    print("pre-0.2.0 development")
                    firmware_release = re.sub(r'\+[a-f0-9]{7}$', '', firmware_name)
                    # kathleen 0.2.0-alpha has some versions w/o git-hash
                    # only fill firmware_base when we have a git-hash
                    temp = firmware_name.lstrip(firmware_release)
                    if len(temp) > 0:
                        firmware_base = temp.lstrip("+")
                        temp = ""
                elif firmware_kathleen1505.match(firmware_name):
                    firmware_release = firmware_name
                elif firmware_openwrt.match(firmware_name):
                    print("old OpenWRT firmware")
                    if  (firmware_name.find("Attitude Adjustment") != -1) or \
                        (firmware_name.find("Barrier Breaker berlin") != -1):
                        print("found AA or BB pberg / berlin")
                        (firmware_release, firmware_base) = firmware_name.split('-')
                    elif firmware_name.find("OpenWrt Chaos Calmer") != -1:
                        (firmware_release, firmware_base) = firmware_name.rsplit(' ', 1)
                    else:
                        print("unknown OpenWrt")
                else:
                    firmware_release = re.sub(r'\+[a-f0-9]{7}$', '', firmware_name)
            elif firmware_kathleen_correct.match(firmware["name"]):
                print("regular firmware data")

                firmware_release = firmware["name"]
                firmware_base = firmware["revision"]
            elif firmware_kathleen_correct_dev.match(firmware["name"]):  # "Freifunk Berlin kathleen 0.2.0-beta+718cff0"
                print("regular development")
                firmware_release = re.sub(r'\+[a-f0-9]{7}$', '', firmware["name"])
                firmware_base = firmware["name"][-7:]
            elif firmware_hedy.match(firmware["name"]):
                print("hedy firmware")
                firmware_release = firmware["name"]
                firmware_base = firmware["revision"]
            elif firmware_falter.match(firmware["name"]):
                print("falter firmware")
                firmware_release = firmware["name"]
                firmware_base = firmware["revision"]
            elif firmware_prekathleen.match(firmware["name"]):  # "Freifunk Berlin 1.1.0-alpha"
                print("pre kathleen firmware")
                firmware_release = firmware["name"]
                firmware_base = firmware["revision"]
            elif firmware_ffb_dev.match(firmware["name"]):  # "Freifunk Berlin Dev-daily"
                print("Freifunk Berlin Dev")
                firmware_release = firmware["name"]
                firmware_base = firmware["revision"]
            elif firmware_potsdam.match(firmware["name"]):  # "Freifunk Potsdam"
                print("Freifunk Potsdam")
                firmware_release = firmware["name"]
                firmware_base = firmware["revision"]
            else:
                print("unknown firmware type")
                firmware_release = firmware.get("name", "unknown")
                firmware_base = firmware.get("revision", "unknown")
            firmware_release = re.sub(r'^Freifunk-Berlin', 'Freifunk Berlin', firmware_release)
            firmware_release = re.sub(r'^Freifunk Berlin hedy', 'Hedy', firmware_release)
            firmware_release = re.sub(r'^Freifunk Berlin kathleen', 'Kathleen', firmware_release) # "Kathleen 0.2.0-beta+718cff0"
            firmware_release = re.sub(r'^OpenWrt Attitude Adjustment', 'OpenWrt AA', firmware_release)
            firmware_release = re.sub(r'^OpenWrt Barrier Breaker', 'OpenWrt BB', firmware_release)
            firmware_release = re.sub(r'^OpenWrt Chaos Calmer', 'OpenWrt CC', firmware_release)
        except:
            print("firmwaredecode exception")
            traceback.print_exc(file=sys.stdout)
            firmware_base = "unknown"
            firmware_release = "unknown"
        print("Firmware release '%s', base '%s'" % (firmware_release, firmware_base))
        return(firmware_base, firmware_release)

nodes = []
graphnodes = dict()
graphlinks = []

def process_node_json(comment, body, ignore_if_offline=True):
    """transforms node data into ffmap format. Does some interpretation on node
       data too (figure out if node has WAN-uplink, etc)"""
    global nodes
    global graphnodes
    global graphlinks
    global update_tests
    try:
        print("Converting " + comment)
        owmnode = json.loads(body)
        firstseen = owmnode["ctime"][:-1]
        lastseen = owmnode["mtime"][:-1]
        lastseensecs = (datetime.datetime.utcnow() - dateutil.parser.parse(lastseen)).total_seconds()
        isonline = lastseensecs < 60*60*2  # assume offline if not seen for more than 2 hours
        if ignore_if_offline and lastseensecs > 60*60*24*7 and not update_tests:
            print("...offline more than a week, skipping")
            return
        longitude = owmnode["longitude"]
        latitude = owmnode["latitude"]
        if not check_location(float(longitude), float(latitude)):
            print("...out of geographic bounds, skipping")
            return

        # special case: fetch whether there is uplink or not for hedy devices. general case below
        try:
            fw_name = owmnode['firmware']['name']
        except:
            fw_name = 'nothing' # Boolean __None__ would result in roughly 40 nodes being dropped.

        site_code = None # TODO Falter hack. Delete later.
        if fw_version_equal_or_more_recent(fw_name, "1.0.0") and not fw_version_equal_or_more_recent(fw_name, "1.1.0"): # hedy firmwares
            isuplink = False
            for iface in owmnode["interfaces"]:
                try:
                    if iface["device"] == "ffuplink":
                        isuplink = True
                        break #avoid further iteration to save computing power
                except:
                    continue
        elif fw_name.startswith("Freifunk ") and fw_version_equal_or_more_recent(fw_name, "1.1.0"):
            # falter-1.1.0 does not send router interfaces anymore. Fetch uplink from olsr config:
            # Does the router announce a gateway?
            isuplink = False
            print("DEBUG: " + str(owmnode["olsr"].get("ipv4Config").get("hasIpv4Gateway")))
            if owmnode["olsr"].get("ipv4Config").get("hasIpv4Gateway") == True or owmnode["olsr"].get("ipv4Config").get("hasIpv6Gateway") == True:
                isuplink = True
                # Dirty fix: just assume that any router which has WAN also shares wifi.
                # TODO: re-enable some information on interfaces in Falter-OWM.lua again
                site_code = "hotspot"
        else:
            # general case: check if the router itself has an uplink via WAN. returns True or False
            isuplink = len([a for a in owmnode.get("interfaces", []) if a.get("ifname", "none") == "ffvpn"]) > 0

        hasclientdhcp = len([a for a in owmnode.get("interfaces", [])
                             if(a.get("encryption", "unknown") == "none" and a.get("mode", "unknown") == "ap")
                               or a.get("ifname", "none") == "br-dhcp"
                            ]) > 0
        if site_code != "hotspot": # TODO Falter hack: delete later
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
            hardware_model = "unknown" if chipset == "unknown" else "unknown (%s)" % chipset
        try:
            email = owmnode["freifunk"]["contact"].get("mail", "")
        except:
            email = ""
        if "firmware" in owmnode:
                (firmware_base, firmware_release) = parse_firmware(owmnode["firmware"])
        else:
            (firmware_base, firmware_release) = ("outdated", "unknown (%s)" % owmnode["script"] if "script" in owmnode else "unknown")
            print("no 'firmware' JSON node found")
            print("Firmware release '%s', base '%s'" % (firmware_release, firmware_base))

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
        print(node)

        if update_tests:
            f_name = f"testdata/data_{url_escape(hostid)}.json"
            if not os.path.isfile(f_name):
                with open(f_name, 'w') as f:
                    f.write(json.dumps({"owmnode": owmnode, "ffmapnode": node}))

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
          print(graphlink)
        graphnodes[hostid] = {"id": hostid, "node_id": hostid, "seq": len(graphnodes)}
        print(graphnodes[hostid])
        print("**********************************")
        return node
    except:
        traceback.print_exc(file=sys.stdout)


def do_regression_test(test_file):
    with open(test_file, 'r') as f:
        previous_data = json.loads(f.read())
        current_ffmap = process_node_json(test_file, json.dumps(previous_data["owmnode"]), ignore_if_offline=False)
        current_str = json.dumps(current_ffmap, sort_keys=True, indent=4)
        previous_str = json.dumps(previous_data["ffmapnode"], sort_keys=True, indent=4)
        assert current_str == previous_str, f"Not equal (current, expected):\n{current_str}\n{previous_str}"


def run_complete_regression_test():
    for f_name in glob(f"testdata/data_*.json"):
        do_regression_test(f_name)
    print("Regression test completed successfully.")


# if you want to test the functions defined above in an interactive way, just start
# the python interpreter, then "from owm2ffmap import (function)", then go crazy.


if __name__ == "__main__":
    if "".join(sys.argv[1:]) == "--tests":
        run_complete_regression_test()
        sys.exit()

    try:
        node_list = json.loads(get_nodes())
    except:
        print("Error accessing api.openwifimap.net")
        node_list = None
        for nodename in os.listdir('/var/opt/ffmapdata/'):
            if nodename.endswith(".json"):
                try:
                    nodefile = '/var/opt/ffmapdata/' + nodename;
                    with open(nodefile, 'r') as myfile:
                        data=myfile.read()
                    nodename = nodename.replace(".json", "")
                    nodename = url_unescape(nodename)
                    process_node_json(nodename, data)
                except Exception as e:
                    print("Error processing node %s (%s), skipping" % (nodename, str(e)))

    timestamp = datetime.datetime.utcnow().isoformat()

    if node_list is not None:
        http_client = httpclient.AsyncHTTPClient()
        for row in node_list["rows"]:
            url = "https://api.openwifimap.net/db/" + row["id"].strip()
            nodejson = cache.get(url, None)
            if nodejson is None:
                i += 1
                http_client.fetch(url, handle_request, method='GET')  # calls process_node_json internally
            else:
                process_node_json(url, nodejson)

        print("Getting %d node infos from api.openwifimap.net" % i)
        if i > 0:
            ioloop.IOLoop.instance().start()
        # node data has been fetched and converted here
    else:
        print("openwifimap seems offline. Using local files.")

    # fixup links in graph.json
    brokenlinks = []
    for link in graphlinks:
      try:
        link["source"] = graphnodes[link["source"]]["seq"]
        link["target"] = graphnodes[link["target"]]["seq"]
      except:
        print("Could not resolve source %s or target %s for graph" % (link["source"], link["target"]))
        brokenlinks.append(link)
    graphlinks = [link for link in graphlinks if link not in brokenlinks]

    graphnodes = [node for _, node in graphnodes.items()]
    graphnodes = sorted(graphnodes, key=lambda x: x["seq"])
    graph = {"batadv": {"directed": False, "graph": [], "links": graphlinks, "multigraph": False, "nodes": graphnodes}, "version": 1}
    print(graph)
    with open("graph.json", "w") as outfile:
        json.dump(graph, outfile)

    # finalize nodes.json
    nodes = {"nodes": nodes, "timestamp": timestamp, "version": 2}
    print(nodes)
    with open("nodes.json", "w") as outfile:
        json.dump(nodes, outfile)

    print("Wrote %d nodes." % len(nodes["nodes"]))

    cache.close()
