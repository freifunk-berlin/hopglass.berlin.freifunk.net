import datetime
import dateutil.parser
import json
import os
import re
import traceback
import sys
import asyncio
from tornado import httpclient
from tornado.escape import url_unescape
from diskcache import Cache
import requests

# This is a quick hack to pull Freifunk node data for a specific geographic area
# from OpenWifiMap (OWM) and to convert it to the format used by Gluon communities
# typically (ffmap-backend, nodes.json and graph.json) in order to be able to use
# it with compatible frontends such as HopGlass.

# The cache is mostly helpful when debugging the script.
# Use /dev/shm ramdisk since that's much faster than real disks on shared VMs
# typically.
cache = Cache("/dev/shm/owm2ffmap_cache")

firmware_prekathleen = re.compile(r"^Freifunk Berlin [0-9]\.*")
firmware_hedy = re.compile(r"^Freifunk Berlin [hH]edy 1\.[0-9]\.[0-9]")
firmware_falter = re.compile(r"^Freifunk Falter [0-9]\.[0-9]\.[0-9]")
firmware_ffb_dev = re.compile("^Freifunk Berlin Dev")
firmware_potsdam = re.compile("^Freifunk Potsdam")
firmware_kathleen_correct = re.compile(r"^Freifunk Berlin kathleen 0\.[2-3]\.0$")
firmware_kathleen_correct_dev = re.compile(
    r"^Freifunk[ -]Berlin [kK]athleen 0\.[2-3]\.0-.*\+[a-f0-9]{7}$"
)
firmware_pre020 = re.compile(r"^Freifunk Berlin kathleen 0\.[0-1]\.[0-2]$")
firmware_pre020_dev = re.compile(r"^Freifunk[ -]Berlin kathleen 0\.[0-2]\.[0-2][ -].*")
firmware_kathleen1505 = re.compile(r"^Freifunk Berlin kathleen 15.05(\.1){0,1}$")
firmware_openwrt = re.compile("^OpenWrt .*")

bounding_box = (
    "12.5,52.1,14.5,52.9"  # Berlin and parts of East Brandenburg (-> Fuerstenwalde)
)
bounding_box_elems = [float(x) for x in bounding_box.split(",")]
date_format = "%Y-%m-%dT%H:%M:%S+0000"
prometheus_url = "http://localhost:9090/api/v1/query?query=collectd_dhcpleases_count{}"
dhcp_clients = {}
nodes = []
graphlinks = []


def get_dhcp_clients():
    global dhcp_clients
    global prometheus_url
    try:
        response = requests.get(prometheus_url, timeout=5)
    except Exception as e:
        print(f"Error accessing Prometheus API: {e}")
        return
    if response.status_code == 200:
        data = response.json()
        if "data" in data and "result" in data["data"]:
            for result in data["data"]["result"]:
                node = result["metric"]["exported_instance"]
                clients = int(result["value"][1])
                dhcp_clients[node] = clients


def fw_version_equal_or_more_recent(
    ver_a,
    ver_b: str,
) -> bool:
    """Returns True if ver_a is a semantic version string and greater
    or equal to ver_b, otherwise False."""
    va_re = re.search(r".*([0-9]+\.[0-9]+\.[0-9]*)", ver_a)
    if not va_re:
        return False
    va = [int(n) for n in va_re.group(1).split(".")]
    vb = [int(n) for n in ver_b.split(".")]
    for i in range(0, 3):
        if va[i] != vb[i]:
            return va[i] > vb[i]
    return True


async def get_nodes():
    """gets a list of all routers within the bounding box from openwifimap"""
    url = "https://api.openwifimap.net/view_nodes_spatial?bbox=" + bounding_box
    if url in cache:
        return cache[url]
    client = httpclient.AsyncHTTPClient()
    response = await client.fetch(url, method="GET", raise_error=False)
    if response.code != 200:
        raise RuntimeError(f"Failed to fetch node list: HTTP {response.code}")
    body = response.body
    cache.set(url, body, expire=60 * 10)
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
    print(f"Firmware (raw): {firmware['name']}/{firmware['revision']}")
    try:
        if "name" in firmware and len(firmware["name"]) == 0:
            firmware_name = firmware[
                "revision"
            ]  # Kathleen < 0.2.0 uses "revision" field for all data
            if firmware_pre020.match(firmware_name):
                print("Kathleen pre-0.2.0")
                firmware_release = firmware_name
                firmware_base = re.sub(
                    r"^Freifunk Berlin kathleen ", "v", firmware_name
                )
            elif firmware_pre020_dev.match(firmware_name):
                print("pre-0.2.0 development")
                firmware_release = re.sub(r"\+[a-f0-9]{7}$", "", firmware_name)
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
                if (firmware_name.find("Attitude Adjustment") != -1) or (
                    firmware_name.find("Barrier Breaker berlin") != -1
                ):
                    print("found AA or BB pberg / berlin")
                    (firmware_release, firmware_base) = firmware_name.split("-")
                elif firmware_name.find("OpenWrt Chaos Calmer") != -1:
                    (firmware_release, firmware_base) = firmware_name.rsplit(" ", 1)
                else:
                    print("unknown OpenWrt")
            else:
                firmware_release = re.sub(r"\+[a-f0-9]{7}$", "", firmware_name)
        elif firmware_kathleen_correct.match(firmware["name"]):
            print("regular firmware data")

            firmware_release = firmware["name"]
            firmware_base = firmware["revision"]
        elif firmware_kathleen_correct_dev.match(
            firmware["name"]
        ):  # "Freifunk Berlin kathleen 0.2.0-beta+718cff0"
            print("regular development")
            firmware_release = re.sub(r"\+[a-f0-9]{7}$", "", firmware["name"])
            firmware_base = firmware["name"][-7:]
        elif firmware_hedy.match(firmware["name"]):
            print("hedy firmware")
            firmware_release = firmware["name"]
            firmware_base = firmware["revision"]
        elif firmware_falter.match(firmware["name"]):
            print("falter firmware")
            firmware_release = firmware["name"]
            firmware_base = firmware["revision"]
        elif firmware_prekathleen.match(
            firmware["name"]
        ):  # "Freifunk Berlin 1.1.0-alpha"
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
        firmware_release = re.sub(
            r"^Freifunk-Berlin", "Freifunk Berlin", firmware_release
        )
        firmware_release = re.sub(r"^Freifunk Berlin hedy", "Hedy", firmware_release)
        firmware_release = re.sub(
            r"^Freifunk Berlin kathleen", "Kathleen", firmware_release
        )  # "Kathleen 0.2.0-beta+718cff0"
        firmware_release = re.sub(
            r"^OpenWrt Attitude Adjustment", "OpenWrt AA", firmware_release
        )
        firmware_release = re.sub(
            r"^OpenWrt Barrier Breaker", "OpenWrt BB", firmware_release
        )
        firmware_release = re.sub(
            r"^OpenWrt Chaos Calmer", "OpenWrt CC", firmware_release
        )
    except:
        print("firmwaredecode exception")
        traceback.print_exc(file=sys.stdout)
        firmware_base = "unknown"
        firmware_release = "unknown"
    print(f"Firmware release '{firmware_release}', base '{firmware_base}'")
    return (firmware_base, firmware_release)


def process_node_json(comment, body, ignore_if_offline=True):
    """transforms node data into ffmap format. Does some interpretation on node
    data too (figure out if node has WAN-uplink, etc)"""
    global nodes
    global graphlinks
    global dhcp_clients
    try:
        print("Converting " + comment)
        owmnode = json.loads(body)
        firstseen = dateutil.parser.parse(owmnode["ctime"][:-1]).astimezone(
            datetime.UTC
        )
        lastseen = dateutil.parser.parse(owmnode["mtime"][:-1]).astimezone(datetime.UTC)
        if lastseen < datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=3):
            isonline = False
        else:
            isonline = True
        if ignore_if_offline and not isonline:
            print("...offline more than a week, skipping")
            return
        longitude = owmnode["longitude"]
        latitude = owmnode["latitude"]
        if not check_location(float(longitude), float(latitude)):
            print("...out of geographic bounds, skipping")
            return

        # special case: fetch whether there is uplink or not for hedy devices. general case below
        try:
            fw_name = owmnode["firmware"]["name"]
        except:
            fw_name = "nothing"  # Boolean __None__ would result in roughly 40 nodes being dropped.

        site_code = None  # TODO Falter hack. Delete later.
        if fw_version_equal_or_more_recent(
            fw_name, "1.0.0"
        ) and not fw_version_equal_or_more_recent(
            fw_name, "1.1.0"
        ):  # hedy firmwares
            isuplink = False
            for iface in owmnode["interfaces"]:
                try:
                    if iface["device"] == "ffuplink":
                        isuplink = True
                        break  # avoid further iteration to save computing power
                except:
                    continue
        elif fw_name.startswith("Freifunk ") and fw_version_equal_or_more_recent(
            fw_name, "1.1.0"
        ):
            # falter-1.1.0 does not send router interfaces anymore. Fetch uplink from olsr config:
            # Does the router announce a gateway?
            isuplink = False
            try:
                if (
                    owmnode["olsr"].get("ipv4Config").get("hasIpv4Gateway") is True
                    or owmnode["olsr"].get("ipv4Config").get("hasIpv6Gateway") is True
                ):
                    isuplink = True
                # Dirty fix: just assume that any router which has WAN also shares wifi.
                # TODO: re-enable some information on interfaces in Falter-OWM.lua again
                site_code = "hotspot"
            except:
                pass
        else:
            # general case: check if the router itself has an uplink via WAN. returns True or False
            isuplink = (
                len(
                    [
                        a
                        for a in owmnode.get("interfaces", [])
                        if a.get("ifname", "none") == "ffvpn"
                    ]
                )
                > 0
            )

        hasclientdhcp = (
            len(
                [
                    a
                    for a in owmnode.get("interfaces", [])
                    if (
                        a.get("encryption", "unknown") == "none"
                        and a.get("mode", "unknown") == "ap"
                    )
                    or a.get("ifname", "none") == "br-dhcp"
                ]
            )
            > 0
        )
        if site_code != "hotspot":  # TODO Falter hack: delete later
            site_code = (
                "hotspot" if hasclientdhcp else "routeronly"
            )  # hack: allow selecting nodes with hotspot functionality via statistics
        try:
            uptime = datetime.datetime.now(datetime.UTC) - datetime.timedelta(
                seconds=owmnode["system"]["uptime"][0]
            )
        except:
            uptime = datetime.datetime.now(datetime.UTC)
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
            if hardware_model.startswith(
                ("Ubiquiti Nanostation M", "Ubiquiti Bullet M", "Ubiquiti Rocket M")
            ):
                # For Ubiquiti routers, add 2.4GHz/5GHz indication
                hardware_model = hardware_model.replace(
                    " M", " M2" if is24ghz else " M5"
                )
        except:
            hardware_model = (
                "unknown" if chipset == "unknown" else "unknown (%s)" % chipset
            )
        try:
            email = owmnode["freifunk"]["contact"].get("mail", "")
        except:
            email = ""
        if "firmware" in owmnode:
            (firmware_base, firmware_release) = parse_firmware(owmnode["firmware"])
        else:
            (firmware_base, firmware_release) = (
                "outdated",
                (
                    "unknown (%s)" % owmnode["script"]
                    if "script" in owmnode
                    else "unknown"
                ),
            )
            print("no 'firmware' JSON node found")
            print(f"Firmware release '{firmware_release}', base '{firmware_base}'")

        # Addresses
        node_addresses = []

        try:
            node_addresses += [
                link["sourceAddr4"]
                for link in owmnode["links"]
                if "sourceAddr4" in link
            ]
            node_addresses.append(owmnode["olsr"]["ipv4Config"]["config"]["mainIp"])
        except KeyError:
            pass
        # Deduplicate list
        node_addresses = sorted(list(set(node_addresses)))

        # Load
        try:
            loadavg = owmnode["system"]["loadavg"][0]
        except KeyError:
            loadavg = "0.0"

        # Clients

        clients = dhcp_clients[hostname] if hostname in dhcp_clients else 0

        # nodeID
        # in gluon this is a mac address, we currently do not have this information
        node_id = str(len(nodes)).zfill(12)

        node = dict(
            firstseen=firstseen.strftime(date_format),
            lastseen=lastseen.strftime(date_format),
            is_online=isonline,
            is_gateway=isuplink,
            clients=clients,
            # clients_wifi24=0,
            # clients_wifi5=0,
            # clients_other=0,
            # clients_owe=0,
            # clients_owe24=0,
            # clients_owe5=0,
            # rootfs_usage=0.0,
            loadavg=loadavg,
            # memory_usage=0.0,
            uptime=uptime.strftime(date_format),
            gateway_nexthop="N/A",  # TODO
            gateway="N/A",  # TODO
            # gateway6="",  # TODO
            node_id=node_id,
            # mac="84:16:f9:9b:bc:0a",
            addresses=node_addresses,
            domain="ffberlin",
            hostname=hostname,
            owner=email,
            location=dict(longitude=longitude, latitude=latitude),
            firmware=dict(
                base=firmware_base,
                release=firmware_release,
                # target="ath79",
                # subtarget="generic",
                # image_name="ubiquiti-unifi-ac-mesh"
            ),
            autoupdater=dict(enabled=False, branch="N/A"),
            # nproc=1,
            model=hardware_model,
        )
        nodes.append(node)

        for link in owmnode.get("links", []):
            targetid = link["id"]
            quality = link["quality"]

            if len(graphlinks) == 0:
                newlink = True

            for existing_link in graphlinks:
                if (existing_link["target_hostname"] == hostid) and (
                    existing_link["source_hostname"] == link["id"]
                ):
                    existing_link["target_tq"] = quality
                    newlink = False
                    break

                elif (existing_link["source_hostname"] == hostid) and (
                    existing_link["target_hostname"] == link["id"]
                ):
                    newlink = False
                    break
                else:
                    newlink = True

            if newlink:
                graphlink = {
                    "source_hostname": hostid,
                    "target_hostname": targetid,
                    "source_tq": quality,
                    "target_tq": quality,
                }
                graphlinks.append(graphlink)

        return node
    except:
        traceback.print_exc(file=sys.stdout)


if __name__ == "__main__":

    async def main():
        # Get dhcp clients from prometheus
        get_dhcp_clients()

        # Try fetching from OWM; on failure, use local files
        try:
            node_list = json.loads(await get_nodes())
        except Exception:
            print("Error accessing api.openwifimap.net")
            node_list = None
            for nodename in os.listdir("/var/opt/ffmapdata/"):
                if nodename.endswith(".json"):
                    try:
                        nodefile = "/var/opt/ffmapdata/" + nodename
                        with open(nodefile) as myfile:
                            data = myfile.read()
                        nodename = nodename.replace(".json", "")
                        nodename = url_unescape(nodename)
                        process_node_json(nodename, data)
                    except Exception as e:
                        print(
                            "Error processing node %s (%s), skipping"
                            % (nodename, str(e))
                        )

        if node_list is not None:
            client = httpclient.AsyncHTTPClient()
            sem = asyncio.Semaphore(50)

            async def fetch_and_process(url: str):
                cached = cache.get(url, None)
                if cached is not None:
                    process_node_json(url, cached)
                    return
                for attempt in range(3):
                    resp = await client.fetch(url, method="GET", raise_error=False)
                    print(
                        f"URL: {url}, code: {resp.code}, bytes: {len(resp.body) if resp.code == 200 else 0}"
                    )
                    if resp.code == 200:
                        cache.set(resp.effective_url, resp.body, expire=60 * 30)
                        process_node_json(resp.effective_url, resp.body)
                        return
                    if resp.code == 599 and attempt < 2:
                        print(f"Timeout for {url}, retrying ({attempt+1}/3)")
                        continue
                    print(f"HTTP {resp.code} for {url}, skipping")
                    return

            tasks = []
            for row in node_list["rows"]:
                url = "https://api.openwifimap.net/db/" + row["id"].strip()

                async def worker(u=url):
                    async with sem:
                        await fetch_and_process(u)

                tasks.append(asyncio.create_task(worker()))
            print(f"Getting {len(tasks)} node infos from api.openwifimap.net")
            if tasks:
                await asyncio.gather(*tasks)
        else:
            print("openwifimap seems offline. Using local files.")

        # Build outputs
        timestamp = datetime.datetime.now(datetime.UTC).strftime(date_format)

        brokenlinks = []
        # Update graphlinks with node_id
        for link in graphlinks:
            source_node = [
                node
                for node in nodes
                if node["hostname"] + ".olsr" == link["source_hostname"]
            ]

            link["source"] = (
                source_node[0]["node_id"] if source_node else brokenlinks.append(link)
            )

            target_node = [
                node
                for node in nodes
                if node["hostname"] + ".olsr" == link["target_hostname"]
            ]
            link["target"] = (
                target_node[0]["node_id"] if target_node else brokenlinks.append(link)
            )

            link["type"] = "unknown"
            # del link["source_hostname"]
            # del link["target_hostname"]

        graphlinks[:] = [link for link in graphlinks if link not in brokenlinks]

        nodes_out = {"timestamp": timestamp, "nodes": nodes, "links": graphlinks}
        with open("nodes_meshviewer.json", "w") as outfile:
            json.dump(nodes_out, outfile)

        print("Wrote %d nodes." % len(nodes_out["nodes"]))

    asyncio.run(main())
    cache.close()
