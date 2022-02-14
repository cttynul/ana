
product_ids = [{"id": "9312", "os": "Windows Server 2008 for 32-bit Systems Service Pack 2"},
                {"id": "10049", "os": "Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)"},
                {"id": "10051", "os": "Windows Server 2008 R2 for x64-based Systems Service Pack 1"},
                {"id": "10287", "os": "Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)"},
                {"id": "10378", "os": "Windows Server 2012"},
                {"id": "10379", "os": "Windows Server 2012 (Server Core installation)"},
                {"id": "10483", "os": "Windows Server 2012 R2"},
                {"id": "10500", "os": "Windows Server 2012 R2 (Server Core installation)"},
                {"id": "10543", "os": "Windows Server 2012 R2 (Server Core installation)"},
                {"id": "10816", "os": "Windows Server 2016"},
                {"id": "10855", "os": "Windows Server 2016 (Server Core installation)"},
                {"id": "11571", "os": "Windows Server 2019"},
                {"id": "11572", "os": "Windows Server 2019 (Server Core installation)"},
                {"id": "11803", "os": "Windows Server, version 20H2 (Server Core Installation)"},
                {"id": "11923", "os": "Windows Server 2022"},
                {"id": "11924", "os": "Windows Server 2022 (Server Core installation)"},
                {"id": "9312", "os": "Windows Server 2008 for 32-bit Systems Service Pack 2"},
                {"id": "9318", "os": "Windows Server 2008 for x64-based Systems Service Pack 2"},
                {"id": "9344", "os": "Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)"}]

def humanize_values(input_list):
    result = []
    for d in input_list:
        for product in product_ids:
            if d["OS"].startswith(product["id"][:-3]):
                el = {"CVE": d["CVE"], "Title": d["Title"], "Patch": d["Patch"], "OS": product["os"]}
                if el not in result: result.append(el)
                
    return result