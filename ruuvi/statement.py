# Ruuvi Gateway & Tags DSL made for research purposes
# Rauli Kaksonen, 2024
# The product is by Ruuvi, Ltd.

# pylint: disable=pointless-statement

from toolsaf.main import Builder, ARP, ICMP, EAPOL, HTTP, BLEAdvertisement, TLS, DHCP, NTP, DNS, UDP, IP, TCP
from toolsaf.common.android import (
    LOCATION, BLUETOOTH, ADMINISTRATIVE, UNCATEGORIZED,
    NETWORK
)

# Define system
system = Builder.new("Ruuvi Gateway & Tags")
system.tag("ruuvi")
system.network(ip_mask="10.42.0.0/16")

# Define any host
any_host = system.any("Service")

# Define gateway
gateway = system.device("Ruuvi Gateway").serve(HTTP)
gateway / ARP / EAPOL

# Define tags
tags = system.device("Ruuvi Tags")

# Define mobile app
mobile_app = system.mobile("Ruuvi App")
mobile_app / ARP / EAPOL

mobile_app.set_permissions(
    LOCATION, BLUETOOTH, ADMINISTRATIVE, UNCATEGORIZED,
    NETWORK
)

# Define browser
browser = system.browser()
browser / ARP

# Define broadcasts
broadcast = system.any("Broadcast")

# BLE advertising data captured with 'btmon' and converted to tshark JSON.
# The capture contains BLE 5.0 extended advertising events which use field
# 'bthci_evt.le_ext_advts_event_type' instead of the legacy 'bthci_evt.le_advts_event_type'
# that the toolsaf expects. The field must be renamed during conversion:
# tshark -r capture.btsnoop -T json -Y "bthci_evt.code == 0x3e" | python3 -c "
#   import json, sys; data = json.load(sys.stdin)
#   for pkt in data:
#       evt = pkt.get('_source',{}).get('layers',{}).get('bthci_evt',{})
#       if 'bthci_evt.le_ext_advts_event_type' in evt:
#           evt['bthci_evt.le_advts_event_type'] = evt['bthci_evt.le_ext_advts_event_type']
#   json.dump(data, sys.stdout)" > ble.tshark.json

# event_type 0x0013 = legacy ADV_IND (connectable, scannable, non-directed)

# without "bthci_evt.code == 0x3e" >> KeyError: 'bthci_evt.bd_addr'
# without evt['bthci_evt.le_advts_event_type'] = evt['bthci_evt.le_ext_advts_event_type'] >> KeyError: 'bthci_evt.le_advts_event_type'

ble_ad = tags.broadcast(BLEAdvertisement(event_type=0x0013))
gateway << ble_ad
mobile_app << ble_ad

multidns = (any_host / UDP(port=5353).multicast("224.0.0.251")).name("mDNS")
igmp = any_host / IP(protocol=2).multicast("224.0.0.251")


# Define backends
firebase = system.backend("firebase").serve(TLS).dns("firebase-settings.crashlytics.com").dns("firebaseinappmessaging.googleapis.com")

google_services = (system.backend("google services")
    .serve(TLS, UDP(port=443), TCP(port=5228))
    .dns("region1.app-measurement.com")
    .dns("app-measurement.com")
    .dns("connectivitycheck.gstatic.com")
    .dns("geller-pa.googleapis.com")
    .dns("taskassist-pa.googleapis.com")
    .dns("www.googleapis.com")
    .dns("cdn-content.ampproject.org")
    .dns("prod-lt-playstoregatewayadapter-pa.googleapis.com")
    .dns("mobile-gtalk.l.google.com")
    .dns("www.gstatic.com")
    .dns("cryptauthdevicesync.googleapis.com")
    .dns("android.googleapis.com")
    .dns("lhr25s10-in-f170.1e100.net")
    .dns("tzhema-ad-in-f2.1e100.net")
)

ruuvi_update = system.backend("ruuvi update").serve(TLS, TCP(port=22), HTTP).dns("fwupdate.ruuvi.com")

ruuvi_network = system.backend("ruuvi network").serve(TLS, UDP(port=443), TCP(port=22), HTTP).dns("network.ruuvi.com").dns("ruuvi.com")

ruuvi_web_ui = system.backend("ruuvi web UI").serve(TLS).dns("webui.ruuvi.com").dns("station.ruuvi.com")

ntp = system.backend("google NTP").serve(NTP).dns("time.google.com").ip("216.239.35.0")

adware = (system.backend("possibly adware")
    .serve(
        TLS,
        TCP(port=22),
        HTTP,
        TCP(port=111),
        UDP(port=111),
        TCP(port=6666),
        TCP(port=7777),
        TCP(port=8100)
    )
    .dns("api.sdk.cqsjd.xyz")
    .dns("imp.adx.cqsjd.xyz")
    .dns("event.sdk.cqsjd.xyz")
)

aws = (system.backend("AWS")
    .serve(TLS, HTTP)
    .dns("s3-r-w.eu-central-1.amazonaws.com")
    .dns("ec2-51-102-227-69.eu-central-1.compute.amazonaws.com")
)

codebase = (system.backend("code base github")
    .serve(TLS, TCP(port=22), HTTP)
    .dns("api.github.com")
    .dns("github.com")
    .dns("release-assets.githubusercontent.com")
    .dns("raw.githubusercontent.com")
)

digicert = (system.backend("digicert")
    .serve(HTTP, TLS, TCP(port=1935))
    .dns("ocsp.digicert.cn.w.cdngslb.com")
    .ip("43.109.101.3")
)

cloudfront = system.backend("cloudfront").serve(TLS, HTTP).dns("d2fw7fwzxnysn2.cloudfront.net")

browser_services = (system.backend("browser/windows services").serve(TLS, HTTP, UDP(port=443))
    .dns("detectportal.firefox.com")
    .dns("ecs.office.com")
    .dns("s-0005.dual-s-msedge.net")
    .dns("oneclient.sfx.ms")
    .dns("a124.dscd.akamai.net")
    .dns("edge.microsoft.com")
    .dns("ax-0002.ax-msedge.net")
    .dns("v20.events.data.microsoft.com")
    .dns("msedge.b.tlu.dl.delivery.mp.microsoft.com")
    .dns("res.public.onecdn.static.microsoft")
    .dns("filedownload.csw.lenovo.com")
    .dns("prod.client.wosc.services.microsoft.com")
    .dns("msedge.api.cdp.microsoft.com")
    .dns("cp801.prod.do.dsp.mp.microsoft.com")
    .dns("settings-win.data.microsoft.com")
    .dns("v10.events.data.microsoft.com")
    .dns("telemetry-incoming.r53-2.services.mozilla.com")
    .dns("glb.api.prod.dcat.dsp.trafficmanager.net")
    .dns("mozilla-ohttp.fastly-edge.com")
    .dns("onedscolprduks02.uksouth.cloudapp.azure.com")
    .dns("res-8.public.onecdn.static.microsoft.cdn.cloudflare.net")
    .dns("e86303.dscx.akamaiedge.net")
    .dns("settings-prod-weu-2.westeurope.cloudapp.azure.com")
    .dns("onedscolprdneu03.northeurope.cloudapp.azure.com")
    .dns("e12437.d.akamaiedge.net")
)

browser.ignore_name_requests("g.live.com", "mr-b01.tm-azurefd.net", "www.bing.com")

# Define SBOMs
google_services.software().sbom(["web_server"])
ruuvi_update.software().sbom(["openssh", "debian_linux", "linux_kernel", "http_server"])
ruuvi_network.software().sbom(["openssh", "ubuntu_linux", "elastic_load_balancing"])
adware.software().sbom(["openssh", "nginx", "lua-nginx-module", "openresty"])
aws.software().sbom(["elastic_load_balancing"])
codebase.software().sbom(["fastly", "varnish_cache"])
digicert.software().sbom(["netscaler_application_delivery_controller"])
cloudfront.software().sbom(["amazon_cloudfront"])

# Define connections
mobile_app >> any_host / DNS / ICMP
mobile_app >> firebase / TLS
mobile_app >> google_services / TLS / HTTP / UDP(port=443)
mobile_app >> ruuvi_network / TLS
mobile_app >> adware / TLS
mobile_app >> aws / TLS
mobile_app >> codebase / TLS
mobile_app >> broadcast / DHCP().broadcast()

gateway >> any_host / DNS
gateway >> ruuvi_network / TLS
gateway >> ruuvi_update / TLS
gateway >> broadcast / DHCP().broadcast()
gateway >> ntp / NTP
gateway >> multidns
gateway >> igmp

browser >> any_host / DNS
browser >> ruuvi_web_ui / TLS
browser >> ruuvi_network / TLS
browser >> browser_services / TLS
browser >> digicert / HTTP
browser >> codebase / TLS
browser >> cloudfront / TLS

# Ignoring non exploitable results
system.ignore(file_type="shodan").properties(
        "shodan:heartbleed"
    ).at().because("Not exploitable")

system.ignore(file_type="testssl").properties(
        "testssl:BREACH",
        "testssl:cert_trust",
        "testssl:CRIME_TLS",
        "testssl:cert_expirationStatus",
        "testssl:cert_notAfter",
        "testssl:fallback_SCSV"
    ).at().because("Not exploitable")


if __name__ == "__main__":
    system.run()
