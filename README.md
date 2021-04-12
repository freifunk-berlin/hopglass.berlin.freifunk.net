https://hopglass.berlin.freifunk.net

...runs an instance of HopGlass
https://github.com/plumpudding/hopglass
that gets its data from the openwifimap backend.
The OWM data is converted to ffmap/hopglass format using
a simple converter (found in owm2ffmap/).
The OWM backend is running on the same server, so owm2ffmap
just parses its data directory.
There's old code that could fetch the OWM data from remote as
well.

In case you wonder, node info ends up in OWM since the
OWM script (see freifunk-berlin/packages) on the node
uploads the data via api.openwifimap.net or
util.berlin.freifunk.net about every hour.

See
https://wiki.freifunk.net/Berlin:Server#hopglass.berlin.freifunk.net
for server details and further links.
