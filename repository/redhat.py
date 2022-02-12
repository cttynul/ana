# https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-29988.xml
# https://access.redhat.com/hydra/rest/securitydata/cve.xml

import requests, xml.dom.minidom

r = requests.get("https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-29988.xml").text
tree = xml.dom.minidom.parseString(r)
collection = tree.documentElement
affecteds = collection.getElementsByTagName("AffectedRelease")
for a in affecteds:
    t = a.getElementsByTagName("Advisory")[0]
    print("RHSA That fix problem: %s" % t.childNodes[0].data)
