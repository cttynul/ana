# https://api.msrc.microsoft.com/cvrf/v2.0/Updates('CVE-2021-28311')
# https://api.msrc.microsoft.com/cvrf/v2.0/cvrf/2021-May

import requests, xml.dom.minidom

def get_kb_from_cve(cve):
    r = requests.get("https://api.msrc.microsoft.com/cvrf/v2.0/Updates('" + cve + "')").json()
    kb_desc = r["value"][0]["CvrfUrl"]
    r = requests.get(kb_desc).text
    tree = xml.dom.minidom.parseString(r)
    collection = tree.documentElement
    affecteds = collection.getElementsByTagName("vuln:Vulnerability")
    result = []
    for a in affecteds:
        #print(a)
        remediations = a.getElementsByTagName("vuln:Remediations")#[0]
        cves_scraped = a.getElementsByTagName("vuln:CVE")
        titles = a.getElementsByTagName("vuln:Title")
        #vuln:Title
        for cve_scraped in cves_scraped:
            if cve == cve_scraped.childNodes[0].data:
                cve_title = titles[cves_scraped.index(cve_scraped)].childNodes[0].data
                for res in remediations:
                    for r in res.getElementsByTagName("vuln:Remediation"):
                        if 1:
                            kb_raw = (r.getElementsByTagName("vuln:Description")[0]).childNodes[0].data
                            if(kb_raw.isdigit()): kb = "KB" + kb_raw
                            else: kb = False
                                #print(kb)
                            #version = (r.getElementsByTagName("vuln:ProductID")[0]).childNodes[0].data
                            version = (r.getElementsByTagName("vuln:ProductID")[0]).childNodes[0].data
                            if(version.startswith("11")): version_effective = "Windows Server 2019"
                            elif(version.startswith("109")): version_effective = "Windows Server 2016"
                            elif(version.startswith("108")): version_effective = "Windows Server 2016"
                            elif(version.startswith("107")): version_effective = "Windows Server 2016"
                            elif(version.startswith("106")): version_effective = "Windows Server 2016"
                            elif(version.startswith("105")): version_effective = "Windows Server 2016"
                            elif(version.startswith("104")): version_effective = "Windows Server 2012 R2"
                            elif(version.startswith("103")): version_effective = "Windows Server 2012"
                            elif(version.startswith("100")): version_effective = "Windows Server 2008 R2"
                            elif(version.startswith("9") or version.startswith("102")): version_effective = "Windows Server 2008"
                            else:version_effective = False
                            if(version_effective):
                                if kb:
                                    el = {"CVE": cve, "Title": cve_title, "Patch": kb, "OS": version_effective}
                                    if el not in result: result.append(el)
                        else:pass
    return result
