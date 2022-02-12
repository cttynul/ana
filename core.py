from repository.microsoft import get_kb_from_cve
from repository.redhat import get_rhsa_from_cve
import pandas as pd

def main():
    CVE_RHSA = "CVE-2021-29988"
    CVE_KB = "CVE-2021-28311"

    rhsa = get_rhsa_from_cve(cve=CVE_RHSA)
    kb = get_kb_from_cve(cve=CVE_KB)

    df_rhsa = pd.DataFrame(rhsa)
    df_kb = pd.DataFrame(kb)

    print(df_rhsa)
    print(df_kb)

    with pd.ExcelWriter(CVE_RHSA + "_RHSA_Report.xlsx") as writer:
        df_rhsa.to_excel(writer, sheet_name=CVE_RHSA, index=False)

    with pd.ExcelWriter(CVE_KB + "_KB_Report.xlsx") as writer:
        df_rhsa.to_excel(writer, sheet_name=CVE_KB, index=False)
