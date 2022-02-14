from repository.microsoft import get_kb_from_cve
from repository.redhat import get_rhsa_from_cve
import pandas as pd
import pathlib

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
    for cve in cves.split(","):
        if os == "WIN": 
            kb = get_kb_from_cve(cve=cve.strip())
            if len(kb) != 0:
                df_kb = pd.DataFrame(kb)
                print(df_kb)
                with pd.ExcelWriter(cve + "_KB_Report.xlsx") as writer:
                    df_kb.to_excel(writer, sheet_name=cve, index=False)
            else:
                print(cve.strip() + " may not be an OS related vulnerability.")
        else:
            rhsa = get_rhsa_from_cve(cve=cve)
            if len(rhsa) != 0:
                df_rhsa = pd.DataFrame(rhsa)
                print(df_rhsa)
                with pd.ExcelWriter(cve + "_RHSA_Report.xlsx") as writer:
                    df_rhsa.to_excel(writer, sheet_name=cve, index=False)
            else:
                print(cve.strip() + " may not be an OS related vulnerability.")


def automagically(cve_input_xls):
    pd_input = pd.read_excel(cve_input_xls, header = 0)
    print(pd_input)
    #result = []
    inputs = pd_input.to_dict("records")
    for i in inputs:
        if "win" in i["OS"].lower() and pathlib.Path("./output/" + i["CVE"] + "_KB_Report.xlsx").exists() is False:
            try: kb = get_kb_from_cve(cve=i["CVE"].strip())
            except: kb = ""
            if len(kb) != 0:
                df_kb = pd.DataFrame(kb)
                print(df_kb)
                with pd.ExcelWriter("./output/" + i["CVE"] + "_KB_Report.xlsx") as writer:
                    df_kb.to_excel(writer, sheet_name=i["CVE"], index=False)
                    #result.append(pd_input.merge(df_kb, on="CVE"))
            else:
                print(i["CVE"].strip() + " may not be an OS related vulnerability.")
        elif "red" in i["OS"].lower() and pathlib.Path("./output/" + i["CVE"] + "_KB_Report.xlsx").exists() is False:
            rhsa = get_rhsa_from_cve(cve=i["CVE"])
            if len(rhsa) != 0:
                df_rhsa = pd.DataFrame(rhsa)
                print(df_rhsa)
                with pd.ExcelWriter("./output/" + i["CVE"] + "_RHSA_Report.xlsx") as writer:
                    df_rhsa.to_excel(writer, sheet_name=i["CVE"], index=False)
                    #result.append(pd_input.merge(df_rhsa, on="CVE"))
            else:
                print(i["CVE"].strip() + " may not be an OS related vulnerability.")
        else:
            print("Report for " + i["CVE"].strip() + " may already been created")
    #print(result)


def main(mode, args=None):
    logo()
    if mode == "wizard": 
        wizard()
        exit(0)
    elif mode == "auto" and args is not None: 
        automagically(cve_input_xls=args)
        exit(0)
    else:
        print("Usage:\n\tpython ana.py [InputFile.xls to automagically generate report|None if you wanna use wizard]")
        exit(1)
    #wizard()
