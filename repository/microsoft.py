# https://api.msrc.microsoft.com/cvrf/v2.0/Updates('CVE-2021-43217')
# https://api.msrc.microsoft.com/cvrf/v2.0/cvrf/2021-May

import requests, xml.dom.minidom
#from support import humanize_ms

product_ids = [{"id": "93", "os": "Windows Server 2008 for 32-bit Systems Service Pack 2"},
                {"id": "100", "os": "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)"},
                {"id": "100", "os": "Windows Server 2008 R2 for x64-based Systems Service Pack 1"},
                {"id": "102", "os": "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)"},
                {"id": "103", "os": "Windows Server 2012"},
                #{"id": "10379", "os": "Windows Server 2012 (Server Core installation)"},
                {"id": "104", "os": "Windows Server 2012 R2"},
                #{"id": "10500", "os": "Windows Server 2012 R2 (Server Core installation)"}, #custom
                {"id": "105", "os": "Windows Server 2012 R2 (Server Core installation)"},
                {"id": "108", "os": "Windows Server 2016"},
                #{"id": "10700", "os": "Windows Server 2016"},#custom
                #{"id": "10600", "os": "Windows Server 2016"},#custom
                #{"id": "10855", "os": "Windows Server 2016 (Server Core installation)"},
                {"id": "115", "os": "Windows Server 2019"},
                #{"id": "11600", "os": "Windows Server 2019"}, #custom
                #{"id": "11700", "os": "Windows Server 2019"}, #custom
                #{"id": "11572", "os": "Windows Server 2019 (Server Core installation)"},
                {"id": "118", "os": "Windows Server, version 20H2 (Server Core Installation)"},
                {"id": "119", "os": "Windows Server 2022"},
                #{"id": "11924", "os": "Windows Server 2022 (Server Core installation)"},
                {"id": "93", "os": "Windows Server 2008 for 32-bit Systems Service Pack 2"},
                {"id": "93", "os": "Windows Server 2008 for x64-based Systems Service Pack 2"},
                {"id": "93", "os": "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)"}]

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
                            version_effective = False
                            
                            for pids in product_ids:
                                if version.startswith(pids["id"]):
                                    version_effective = pids["os"]
                                if version_effective == pids["os"]: break
                            
                            if(version_effective):
                                if kb:
                                    el = {"CVE": cve, "Title": cve_title, "Patch": kb, "OS": version_effective}
                                    if el not in result: result.append(el)
                        else:pass
    return result
    #return humanize_ms.humanize_values(result)
