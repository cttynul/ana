# https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-29988.xml
# https://access.redhat.com/hydra/rest/securitydata/cve.xml

import requests, xml.dom.minidom

def get_rhsa_from_cve(cve):
    r = requests.get("https://access.redhat.com/hydra/rest/securitydata/cve/" + cve + ".xml").text
    tree = xml.dom.minidom.parseString(r)
    collection = tree.documentElement
    affecteds = collection.getElementsByTagName("AffectedRelease")
    cve_title = collection.getElementsByTagName("Bugzilla")[0].childNodes[0].data.strip()
    result = []
    for a in affecteds:
        rhsa = a.getElementsByTagName("Advisory")[0].childNodes[0].data
        os = a.getElementsByTagName("ProductName")[0].childNodes[0].data
        result.append({"CVE": cve, "Title": cve_title, "Patch":rhsa, "OS": os})
    return result
