import asyncio
import datetime
import json
import os
import re
import sys
import traceback
from glob import glob

import dateutil.parser
from diskcache import Cache
from tornado import httpclient
from tornado.escape import url_escape, url_unescape

# This is a quick hack to pull Freifunk node data for a specific geographic area
# from OpenWifiMap (OWM) and to convert it to the format used by Gluon communities
# typically (ffmap-backend, nodes.json and graph.json) in order to be able to use
# it with compatible frontends such as HopGlass.

# The cache is mostly helpful when debugging the script.
# Use /dev/shm ramdisk since that's much faster than real disks on shared VMs.
cache = Cache(
    "/dev/shm/owm2ffmap_cache"
)  # nosec B108: intentional use of tmpfs for speed

firmware_prekathleen = re.compile(r"^Freifunk Berlin [0-9]\.*")
firmware_hedy = re.compile(r"^Freifunk Berlin [hH]edy 1\.[0-9]\.[0-9]")
firmware_falter = re.compile(r"^Freifunk Falter [0-9]\.[0-9]\.[0-9]")
firmware_ffb_dev = re.compile(r"^Freifunk Berlin Dev")
firmware_potsdam = re.compile(r"^Freifunk Potsdam")
firmware_kathleen_correct = re.compile(r"^Freifunk Berlin kathleen 0\.[2-3]\.0$")
firmware_kathleen_correct_dev = re.compile(
    r"^Freifunk[ -]Berlin [kK]athleen 0\.[2-3]\.0-.*\+[a-f0-9]{7}$"
)
firmware_pre020 = re.compile(r"^Freifunk Berlin kathleen 0\.[0-1]\.[0-2]$")
firmware_pre020_dev = re.compile(r"^Freifunk[ -]Berlin kathleen 0\.[0-2]\.[0-2][ -].*")
firmware_kathleen1505 = re.compile(r"^Freifunk Berlin kathleen 15\.05(\.1){0,1}$")
firmware_openwrt = re.compile(r"^OpenWrt .*")

bounding_box = (
    "12.9,52.27,14.12,52.7"  # Berlin and parts of East Brandenburg (-> Fuerstenwalde)
)
bounding_box_elems = [float(x) for x in bounding_box.split(",")]

update_tests = "".join(sys.argv[1:]) == "--update-tests"


def fw_version_equal_or_more_recent(ver_a: str, ver_b: str) -> bool:
    """Return True if ver_a is a semantic version string and >= ver_b."""
    va_re = re.search(r".*([0-9]+\.[0-9]+\.[0-9]*)", ver_a)
    if not va_re:
        return False
    va = [int(n) for n in va_re.group(1).split(".")]
    vb = [int(n) for n in ver_b.split(".")]
    for i in range(0, 3):
        if va[i] != vb[i]:
            return va[i] > vb[i]
    return True


async def fetch_with_retries(
    url: str,
    client: httpclient.AsyncHTTPClient,
    *,
    retries: int = 3,
    timeout: float = 30.0,
    backoff: float = 1.0,
):
    """Fetch a URL with retries/backoff; on success, process the node JSON."""
    cached = cache.get(url, None)
    if cached is not None:
        process_node_json(url, cached)
        return

    for attempt in range(1, retries + 1):
        try:
            resp = await client.fetch(url, method="GET", request_timeout=timeout)
            print(
                "URL: %s, code: %d, bytes: %d"
                % (
                    resp.effective_url,
                    resp.code,
                    len(resp.body) if resp.code == 200 else 0,
                )
            )
            if resp.code == 200:
                cache.set(resp.effective_url, resp.body, expire=60 * 30)
                process_node_json(resp.effective_url, resp.body)
                return
        except httpclient.HTTPError as e:
            print(f"HTTP error fetching {url}: {e}")
            if attempt == retries:
                print(f"Giving up on {url} after {retries} attempts.")
                return
        except Exception as e:
            print(f"Unexpected error fetching {url}: {e}")
            if attempt == retries:
                print(f"Giving up on {url} after {retries} attempts.")
                return
        await asyncio.sleep(backoff * attempt)


async def get_nodes_async():
    """Get list of all routers within the bounding box from openwifimap (async)."""
    url = "https://api.openwifimap.net/view_nodes_spatial?bbox=" + bounding_box
    cached = cache.get(url, None)
    if cached is not None:
        return cached
    client = httpclient.AsyncHTTPClient()
    resp = await client.fetch(url, method="GET", request_timeout=30.0)
    body = resp.body
    cache.set(url, body, expire=60 * 10)
    return body


def check_location(lonE, latN):
    """Exclude all routers outside the boundary box from processing."""
    if not bounding_box_elems[0] < float(lonE) < bounding_box_elems[2]:
        return False
    if not bounding_box_elems[1] < float(latN) < bounding_box_elems[3]:
        return False
    return True


def parse_firmware(firmware):
    """Extract firmware data from OWM data and return base and release."""
    firmware_base = "unknown"
    firmware_release = "unknown"
    print(
        "Firmware (raw): {}/{}".format(firmware.get("name"), firmware.get("revision"))
    )
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
                temp = firmware_name.lstrip(firmware_release)
                if len(temp) > 0:
                    firmware_base = temp.lstrip("+")
            elif firmware_kathleen1505.match(firmware_name):
                firmware_release = firmware_name
            elif firmware_openwrt.match(firmware_name):
                print("old OpenWRT firmware")
                if ("Attitude Adjustment" in firmware_name) or (
                    "Barrier Breaker berlin" in firmware_name
                ):
                    print("found AA or BB pberg / berlin")
                    (firmware_release, firmware_base) = firmware_name.split("-")
                elif "OpenWrt Chaos Calmer" in firmware_name:
                    (firmware_release, firmware_base) = firmware_name.rsplit(" ", 1)
                else:
                    print("unknown OpenWrt")
            else:
                firmware_release = re.sub(r"\+[a-f0-9]{7}$", "", firmware_name)
        elif firmware_kathleen_correct.match(firmware.get("name", "")):
            print("regular firmware data")
            firmware_release = firmware["name"]
            firmware_base = firmware["revision"]
        elif firmware_kathleen_correct_dev.match(firmware.get("name", "")):
            print("regular development")
            firmware_release = re.sub(r"\+[a-f0-9]{7}$", "", firmware["name"])
            firmware_base = firmware["name"][-7:]
        elif firmware_hedy.match(firmware.get("name", "")):
            print("hedy firmware")
            firmware_release = firmware["name"]
            firmware_base = firmware["revision"]
        elif firmware_falter.match(firmware.get("name", "")):
            print("falter firmware")
            firmware_release = firmware["name"]
            firmware_base = firmware["revision"]
        elif firmware_prekathleen.match(firmware.get("name", "")):
            print("pre kathleen firmware")
            firmware_release = firmware["name"]
            firmware_base = firmware["revision"]
        elif firmware_ffb_dev.match(firmware.get("name", "")):
            print("Freifunk Berlin Dev")
            firmware_release = firmware["name"]
            firmware_base = firmware["revision"]
        elif firmware_potsdam.match(firmware.get("name", "")):
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
        )
        firmware_release = re.sub(
            r"^OpenWrt Attitude Adjustment", "OpenWrt AA", firmware_release
        )
        firmware_release = re.sub(
            r"^OpenWrt Barrier Breaker", "OpenWrt BB", firmware_release
        )
        firmware_release = re.sub(
            r"^OpenWrt Chaos Calmer", "OpenWrt CC", firmware_release
        )
    except Exception:
        print("firmwaredecode exception")
        traceback.print_exc(file=sys.stdout)
        firmware_base = "unknown"
        firmware_release = "unknown"
    print("Firmware release '{}', base '{}'".format(firmware_release, firmware_base))
    return (firmware_base, firmware_release)


nodes = []
graphnodes = {}
graphlinks = []


def process_node_json(comment, body, ignore_if_offline: bool = True):
    """Transform OWM node data into ffmap format and collect graph details."""
    global nodes, graphnodes, graphlinks, update_tests
    try:
        print("Converting " + comment)
        owmnode = json.loads(body)

        firstseen = owmnode["ctime"][:-1]
        lastseen = owmnode["mtime"][:-1]
        lastseensecs = (
            datetime.datetime.utcnow() - dateutil.parser.parse(lastseen)
        ).total_seconds()
        isonline = lastseensecs < 60 * 60 * 2
        if ignore_if_offline and lastseensecs > 60 * 60 * 24 * 7 and not update_tests:
            print("...offline more than a week, skipping")
            return

        longitude = owmnode["longitude"]
        latitude = owmnode["latitude"]
        if not check_location(float(longitude), float(latitude)):
            print("...out of geographic bounds, skipping")
            return

        # Determine uplink capability
        fw_name = owmnode.get("firmware", {}).get("name", "nothing")
        site_code = None
        if fw_version_equal_or_more_recent(
            fw_name, "1.0.0"
        ) and not fw_version_equal_or_more_recent(fw_name, "1.1.0"):
            isuplink = any(
                iface.get("device") == "ffuplink"
                for iface in owmnode.get("interfaces", [])
            )
        elif fw_name.startswith("Freifunk ") and fw_version_equal_or_more_recent(
            fw_name, "1.1.0"
        ):
            isuplink = False
            print(
                "DEBUG: " + str(owmnode["olsr"].get("ipv4Config").get("hasIpv4Gateway"))
            )
            if (
                owmnode["olsr"].get("ipv4Config").get("hasIpv4Gateway") is True
                or owmnode["olsr"].get("ipv4Config").get("hasIpv6Gateway") is True
            ):
                isuplink = True
                site_code = "hotspot"
        else:
            isuplink = any(
                a.get("ifname", "none") == "ffvpn"
                for a in owmnode.get("interfaces", [])
            )

        hasclientdhcp = any(
            (
                a.get("encryption", "unknown") == "none"
                and a.get("mode", "unknown") == "ap"
            )
            or a.get("ifname", "none") == "br-dhcp"
            for a in owmnode.get("interfaces", [])
        )
        if site_code != "hotspot":
            site_code = "hotspot" if hasclientdhcp else "routeronly"

        try:
            uptimesecs = owmnode["system"]["uptime"][0]
        except Exception:
            uptimesecs = 0

        hostid = owmnode["_id"]
        hostname = owmnode["hostname"]

        # Detect 2.4/5GHz based on channel numbers
        is24ghz = True
        for interface in owmnode.get("interfaces", []):
            ch = interface.get("channel")
            try:
                if ch is not None and int(ch) > 15:
                    is24ghz = False
            except (TypeError, ValueError):
                continue

        try:
            chipset = owmnode.get("hardware", "unknown").strip()
        except Exception:
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
        except Exception:
            hardware_model = (
                "unknown" if chipset == "unknown" else "unknown (%s)" % chipset
            )

        try:
            email = owmnode["freifunk"]["contact"].get("mail", "")
        except Exception:
            email = ""

        if "firmware" in owmnode:
            firmware_base, firmware_release = parse_firmware(owmnode["firmware"])
        else:
            firmware_base, firmware_release = (
                "outdated",
                (
                    "unknown (%s)" % owmnode.get("script")
                    if "script" in owmnode
                    else "unknown"
                ),
            )
            print("no 'firmware' JSON node found")
            print(
                "Firmware release '{}', base '{}'".format(
                    firmware_release, firmware_base
                )
            )

        node = {
            "firstseen": firstseen,
            "flags": {"online": isonline, "uplink": isuplink},
            "lastseen": lastseen,
            "nodeinfo": {
                "hardware": {"model": hardware_model, "nproc": 1},
                "hostname": hostname,
                "location": {"latitude": latitude, "longitude": longitude},
                # "network": {"addresses": False, "mac": False, "mesh": False},
                "node_id": hostid,
                "owner": {"contact": email},
                "software": {
                    "firmware": {"base": firmware_base, "release": firmware_release}
                },
                "system": {"role": "node", "site_code": site_code},
            },
            "statistics": {"clients": 0, "uptime": uptimesecs},
        }
        nodes.append(node)
        print(node)

        if update_tests:
            f_name = f"testdata/data_{url_escape(hostid)}.json"
            if not os.path.isfile(f_name):
                with open(f_name, "w") as f:
                    f.write(json.dumps({"owmnode": owmnode, "ffmapnode": node}))

        for link in owmnode.get("links", []):
            targetid = link["id"]
            quality = link["quality"]
            quality = 1.0 / float(quality) if quality > 0 else 999
            graphlink = {
                "bidirect": True,
                "source": hostid,
                "target": targetid,
                "tq": quality,
                "vpn": False,
            }
            graphlinks.append(graphlink)
            print(graphlink)

        graphnodes[hostid] = {"id": hostid, "node_id": hostid, "seq": len(graphnodes)}
        print(graphnodes[hostid])
        print("**********************************")
        return node
    except Exception:
        traceback.print_exc(file=sys.stdout)


def do_regression_test(test_file):
    with open(test_file) as f:
        previous_data = json.loads(f.read())
        current_ffmap = process_node_json(
            test_file, json.dumps(previous_data["owmnode"]), ignore_if_offline=False
        )
        current_str = json.dumps(current_ffmap, sort_keys=True, indent=4)
        previous_str = json.dumps(previous_data["ffmapnode"], sort_keys=True, indent=4)
        if current_str != previous_str:
            raise AssertionError(
                f"Not equal (current, expected):\n{current_str}\n{previous_str}"
            )


def run_complete_regression_test():
    for f_name in glob("testdata/data_*.json"):
        do_regression_test(f_name)
    print("Regression test completed successfully.")


async def main_async():
    if "".join(sys.argv[1:]) == "--tests":
        run_complete_regression_test()
        return

    # Try to get list of nodes from OWM
    node_list = None
    try:
        node_list = json.loads(await get_nodes_async())
    except Exception as e:
        print("Error accessing api.openwifimap.net: %s" % e)

    timestamp = datetime.datetime.utcnow().isoformat()

    if node_list is not None:
        client = httpclient.AsyncHTTPClient()
        sem = asyncio.Semaphore(50)

        async def worker(url: str):
            async with sem:
                await fetch_with_retries(
                    url, client, retries=3, timeout=30.0, backoff=1.0
                )

        tasks = []
        for row in node_list.get("rows", []):
            url = "https://api.openwifimap.net/db/" + row["id"].strip()
            nodejson = cache.get(url, None)
            if nodejson is not None:
                process_node_json(url, nodejson)
            else:
                tasks.append(asyncio.create_task(worker(url)))

        if tasks:
            print(f"Fetching {len(tasks)} node infos from api.openwifimap.net")
            await asyncio.gather(*tasks)
        else:
            print("All node infos served from cache.")
    else:
        print("openwifimap seems offline. Using local files.")
        for nodename in os.listdir("/var/opt/ffmapdata/"):
            if nodename.endswith(".json"):
                try:
                    nodefile = "/var/opt/ffmapdata/" + nodename
                    with open(nodefile) as myfile:
                        data = myfile.read()
                    nodename_clean = url_unescape(nodename.replace(".json", ""))
                    process_node_json(nodename_clean, data)
                except Exception as e:
                    print(
                        "Error processing node {} ({}), skipping".format(
                            nodename, str(e)
                        )
                    )

    # fixup links in graph.json
    brokenlinks = []
    for link in graphlinks:
        try:
            link["source"] = graphnodes[link["source"]]["seq"]
            link["target"] = graphnodes[link["target"]]["seq"]
        except Exception:
            print(
                "Could not resolve source {} or target {} for graph".format(
                    link.get("source"), link.get("target")
                )
            )
            brokenlinks.append(link)
    graphlinks[:] = [link for link in graphlinks if link not in brokenlinks]

    graphnodes_list = sorted(
        [node for _, node in graphnodes.items()], key=lambda x: x["seq"]
    )
    graph = {
        "batadv": {
            "directed": False,
            "graph": [],
            "links": graphlinks,
            "multigraph": False,
            "nodes": graphnodes_list,
        },
        "version": 1,
    }
    print(graph)
    with open("graph.json", "w") as outfile:
        json.dump(graph, outfile)

    nodes_obj = {"nodes": nodes, "timestamp": timestamp, "version": 2}
    print(nodes_obj)
    with open("nodes.json", "w") as outfile:
        json.dump(nodes_obj, outfile)

    print("Wrote %d nodes." % len(nodes_obj["nodes"]))

    cache.close()


if __name__ == "__main__":
    asyncio.run(main_async())
