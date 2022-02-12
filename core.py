from repository.microsoft import get_kb_from_cve
from repository.redhat import get_rhsa_from_cve
import pandas as pd

def logo():
    print('''                                           
          .---.   ___ .-.     .---.  
         / .-, \ (   )   \   / .-, \ 
        (__) ; |  |  .-. .  (__) ; | 
          .'`  |  | |  | |    .'`  | 
         / .'| |  | |  | |   / .'| | 
        | /  | |  | |  | |  | /  | | 
        ; |  ; |  | |  | |  ; |  ; | 
        ' `-'  |  | |  | |  ' `-'  | 
        `.__.'_. (___)(___) `.__.'_.
        
                            -cttynul\n''')

def wizard():
    os = ""
    cves = ""
    os = input("Input target OS [RH|WIN] > ")
    cves = input("Input CVEs, multiple input must be separated by a comma [CVE-123, CVE-345] > ")
    print(cves.split(","))
    for cve in cves.split(","):
        if os == "WIN": 
            kb = get_kb_from_cve(cve=cve.strip())
            df_kb = pd.DataFrame(kb)
            print(df_kb)
            with pd.ExcelWriter(cve + "_KB_Report.xlsx") as writer:
                df_kb.to_excel(writer, sheet_name=cve, index=False)
        else:
            rhsa = get_rhsa_from_cve(cve=cve)
            df_rhsa = pd.DataFrame(rhsa)
            print(df_rhsa)
            with pd.ExcelWriter(cve + "_RHSA_Report.xlsx") as writer:
                df_rhsa.to_excel(writer, sheet_name=cve, index=False)


def main():
    logo()
    CVE_RHSA = "CVE-2021-29988"
    CVE_KB = "CVE-2021-28311"
    wizard()
