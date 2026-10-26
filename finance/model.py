"""Illustrative 3-year unit-economics model. Every number below is an ASSUMPTION to replace with real data.

Run: python finance/model.py
"""

PARAMS = {
    "price": 1999,
    "units": [
        5000,
        40000,
        150000
    ],
    "unit": "subscribers",
    "var_cost": 450,
    "share_out": 0.0,
    "fixed": [
        8000000,
        24000000,
        60000000
    ],
    "cac": 400
}


def project(p=PARAMS):
    rows = []
    for year, (units, fixed) in enumerate(zip(p["units"], p["fixed"]), start=1):
        revenue = units * p["price"]
        variable = units * p["var_cost"] + revenue * p["share_out"]
        acquisition = units * p["cac"] * (1 if year == 1 else 0.5)  # assume half of units are repeat after year 1
        profit = revenue - variable - acquisition - fixed
        rows.append((year, units, revenue, variable, acquisition, fixed, profit))
    return rows


if __name__ == "__main__":
    print(f"{'Year':<5}{'subscribers':>14}{'Revenue':>16}{'Variable':>16}{'Acquisition':>16}{'Fixed':>16}{'Profit':>16}  (INR)")
    for r in project():
        print(f"{r[0]:<5}{r[1]:>14,}{r[2]:>16,.0f}{r[3]:>16,.0f}{r[4]:>16,.0f}{r[5]:>16,.0f}{r[6]:>16,.0f}")
