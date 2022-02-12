# https://api.msrc.microsoft.com/cvrf/v2.0/Updates('CVE-2021-28311')
# https://api.msrc.microsoft.com/cvrf/v2.0/cvrf/2021-May

import requests, xml.dom.minidom

r = requests.get("https://api.msrc.microsoft.com/cvrf/v2.0/Updates('CVE-2021-27079')").json()
kb_desc = r["value"][0]["CvrfUrl"]
r = requests.get(kb_desc).text
tree = xml.dom.minidom.parseString(r)
collection = tree.documentElement
affecteds = collection.getElementsByTagName("vuln:Vulnerability")
for a in affecteds:
    #print(a)
    remediations = a.getElementsByTagName("vuln:Remediations")#[0]
    for r in remediations:
        if 1:
            kb_raw = (r.getElementsByTagName("vuln:Description")[0]).childNodes[0].data
            if(kb_raw.isdigit()):
                kb = "KB" + kb_raw
                print(kb)
            #version = (r.getElementsByTagName("vuln:ProductID")[0]).childNodes[0].data
            versions = (r.getElementsByTagName("vuln:ProductID"))
            for v in versions:
                version_effective = False
                version = v.childNodes[0].data
                #if(version.startswith("114")): version_effective = "Windows 10"
                if(version.startswith("115")): version_effective = "Windows Server 2019"
                elif(version.startswith("108")): version_effective = "Windows Server 2016"
                elif(version.startswith("104")): version_effective = "Windows Server 2012 R2"
                elif(version.startswith("103")): version_effective = "Windows Server 2012"
                elif(version.startswith("100")): version_effective = "Windows Server 2008 R2"
                elif(version.startswith("9") or version.startswith("102")): version_effective = "Windows Server 2008"
                else:version_effective = False
                if(version_effective):
                    print(version_effective)
        else:pass
    #print("KB That fix problem: %s" % t.childNodes[0].data)

