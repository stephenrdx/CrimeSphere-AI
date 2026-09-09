import pandas as pd
import random
from faker import Faker
from pathlib import Path

fake = Faker("en_IN")
random.seed(42)

# Create output folder
OUTPUT = Path("data/raw")
OUTPUT.mkdir(parents=True, exist_ok=True)

# -----------------------------
# 1. PERSONS
# -----------------------------

persons = []

for i in range(1, 151):
    persons.append({
        "person_id": f"P{i:03d}",
        "name": fake.name(),
        "age": random.randint(18, 60),
        "gender": random.choice(["Male", "Female"]),
        "occupation": random.choice([
            "Business", "Driver", "Employee",
            "Student", "Trader", "Mechanic", "Unknown"
        ]),
        "city": random.choice([
            "Vijayawada", "Guntur", "Hyderabad",
            "Visakhapatnam", "Bhimavaram", "Rajahmundry"
        ])
    })

persons_df = pd.DataFrame(persons)
persons_df.to_csv(OUTPUT / "persons.csv", index=False)


# -----------------------------
# 2. PHONES
# -----------------------------

phones = []

for i in range(1, 251):
    phones.append({
        "phone_id": f"PH{i:03d}",
        "phone_number": fake.numerify("9#########"),
        "person_id": f"P{random.randint(1, 150):03d}",
        "operator": random.choice(["Jio", "Airtel", "Vi", "BSNL"])
    })

phones_df = pd.DataFrame(phones)
phones_df.to_csv(OUTPUT / "phones.csv", index=False)


# -----------------------------
# 3. VEHICLES
# -----------------------------

vehicles = []

for i in range(1, 51):
    vehicles.append({
        "vehicle_id": f"V{i:03d}",
        "registration_number": f"AP{random.randint(1, 99):02d}"
                                f"{random.choice(['AB','CD','EF','GH'])}"
                                f"{random.randint(1000,9999)}",
        "vehicle_type": random.choice(["Car", "Bike", "Truck", "Auto"]),
        "owner_person_id": f"P{random.randint(1,150):03d}"
    })

vehicles_df = pd.DataFrame(vehicles)
vehicles_df.to_csv(OUTPUT / "vehicles.csv", index=False)


# -----------------------------
# 4. BANK ACCOUNTS
# -----------------------------

accounts = []

for i in range(1, 151):
    accounts.append({
        "account_id": f"BA{i:03d}",
        "account_number": fake.numerify("################"),
        "person_id": f"P{i:03d}",
        "bank": random.choice([
            "SBI", "HDFC", "ICICI", "Axis", "Canara"
        ])
    })

accounts_df = pd.DataFrame(accounts)
accounts_df.to_csv(OUTPUT / "bank_accounts.csv", index=False)


# -----------------------------
# 5. ORGANIZATIONS
# -----------------------------

organizations = []

for i in range(1, 31):
    organizations.append({
        "organization_id": f"O{i:03d}",
        "name": fake.company(),
        "type": random.choice([
            "Company", "Shop", "NGO", "Association"
        ]),
        "city": random.choice([
            "Vijayawada", "Guntur", "Hyderabad",
            "Visakhapatnam"
        ])
    })

organizations_df = pd.DataFrame(organizations)
organizations_df.to_csv(OUTPUT / "organizations.csv", index=False)


# -----------------------------
# 6. LOCATIONS
# -----------------------------

locations = []

for i in range(1, 31):
    locations.append({
        "location_id": f"L{i:03d}",
        "location_name": f"Location_{i}",
        "city": random.choice([
            "Vijayawada", "Guntur", "Hyderabad",
            "Visakhapatnam", "Bhimavaram"
        ]),
        "latitude": round(random.uniform(16.2, 17.5), 6),
        "longitude": round(random.uniform(80.0, 82.0), 6)
    })

locations_df = pd.DataFrame(locations)
locations_df.to_csv(OUTPUT / "locations.csv", index=False)


# -----------------------------
# 7. CASES / FIR
# -----------------------------

cases = []

for i in range(1, 101):
    cases.append({
        "case_id": f"C{i:03d}",
        "fir_number": f"FIR-{2026}-{i:04d}",
        "crime_type": random.choice([
            "Fraud", "Theft", "Robbery",
            "Cybercrime", "Assault", "Smuggling"
        ]),
        "case_date": fake.date_between(
            start_date="-3y",
            end_date="today"
        ),
        "location_id": f"L{random.randint(1,30):03d}"
    })

cases_df = pd.DataFrame(cases)
cases_df.to_csv(OUTPUT / "cases.csv", index=False)


# -----------------------------
# 8. DEVICES
# -----------------------------

devices = []

for i in range(1, 201):
    devices.append({
        "device_id": f"D{i:03d}",
        "device_type": random.choice([
            "Mobile", "Laptop", "Tablet"
        ]),
        "person_id": f"P{random.randint(1,150):03d}"
    })

devices_df = pd.DataFrame(devices)
devices_df.to_csv(OUTPUT / "devices.csv", index=False)


# -----------------------------
# 9. CDR RECORDS
# -----------------------------

cdr = []

for i in range(1, 3001):

    caller = random.randint(1, 150)
    receiver = random.randint(1, 150)

    while receiver == caller:
        receiver = random.randint(1, 150)

    cdr.append({
        "cdr_id": f"CDR{i:04d}",
        "caller_person_id": f"P{caller:03d}",
        "receiver_person_id": f"P{receiver:03d}",
        "duration_seconds": random.randint(10, 1800),
        "call_date": fake.date_between(
            start_date="-1y",
            end_date="today"
        )
    })

cdr_df = pd.DataFrame(cdr)
cdr_df.to_csv(OUTPUT / "cdr_records.csv", index=False)


# -----------------------------
# 10. FINANCIAL TRANSACTIONS
# -----------------------------

transactions = []

for i in range(1, 1501):

    sender = random.randint(1, 150)
    receiver = random.randint(1, 150)

    while receiver == sender:
        receiver = random.randint(1, 150)

    transactions.append({
        "transaction_id": f"T{i:04d}",
        "sender_person_id": f"P{sender:03d}",
        "receiver_person_id": f"P{receiver:03d}",
        "amount": round(random.uniform(500, 100000), 2),
        "transaction_date": fake.date_between(
            start_date="-1y",
            end_date="today"
        ),
        "transaction_type": random.choice([
            "UPI", "NEFT", "IMPS", "Bank Transfer"
        ])
    })

transactions_df = pd.DataFrame(transactions)
transactions_df.to_csv(OUTPUT / "transactions.csv", index=False)


# -----------------------------
# 11. VEHICLE EVENTS
# -----------------------------

vehicle_events = []

for i in range(1, 1001):
    vehicle_events.append({
        "event_id": f"VE{i:04d}",
        "vehicle_id": f"V{random.randint(1,50):03d}",
        "person_id": f"P{random.randint(1,150):03d}",
        "location_id": f"L{random.randint(1,30):03d}",
        "event_date": fake.date_between(
            start_date="-1y",
            end_date="today"
        )
    })

vehicle_events_df = pd.DataFrame(vehicle_events)
vehicle_events_df.to_csv(
    OUTPUT / "vehicle_events.csv",
    index=False
)


# -----------------------------
# 12. LOCATION EVENTS
# -----------------------------

location_events = []

for i in range(1, 1501):
    location_events.append({
        "event_id": f"LE{i:04d}",
        "person_id": f"P{random.randint(1,150):03d}",
        "location_id": f"L{random.randint(1,30):03d}",
        "event_date": fake.date_between(
            start_date="-1y",
            end_date="today"
        )
    })

location_events_df = pd.DataFrame(location_events)
location_events_df.to_csv(
    OUTPUT / "location_events.csv",
    index=False
)


# -----------------------------
# 13. SURVEILLANCE EVENTS
# -----------------------------

surveillance = []

for i in range(1, 501):
    surveillance.append({
        "surveillance_id": f"S{i:03d}",
        "person_id": f"P{random.randint(1,150):03d}",
        "location_id": f"L{random.randint(1,30):03d}",
        "observation": random.choice([
            "Meeting observed",
            "Vehicle observed",
            "Person entering location",
            "Person leaving location",
            "Unknown activity"
        ]),
        "observation_date": fake.date_between(
            start_date="-1y",
            end_date="today"
        )
    })

surveillance_df = pd.DataFrame(surveillance)
surveillance_df.to_csv(
    OUTPUT / "surveillance_events.csv",
    index=False
)


# -----------------------------
# 14. CASE ASSOCIATIONS
# -----------------------------

associations = []

for i in range(1, 501):
    associations.append({
        "association_id": f"CA{i:03d}",
        "case_id": f"C{random.randint(1,100):03d}",
        "person_id": f"P{random.randint(1,150):03d}",
        "relationship": random.choice([
            "Suspect",
            "Witness",
            "Victim",
            "Associate",
            "Person Mentioned"
        ])
    })

associations_df = pd.DataFrame(associations)

associations_df.to_csv(
    OUTPUT / "case_associations.csv",
    index=False
)


# -----------------------------
# FINAL MESSAGE
# -----------------------------

print("\n===================================")
print("14 DATASETS CREATED SUCCESSFULLY")
print("===================================")

for file in OUTPUT.glob("*.csv"):
    print(file.name)