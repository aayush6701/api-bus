from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordRequestForm
from models import SuperAdminRegister, DriverRegister, StudentRegister, StudentLogin, StudentProfile,StudentSecureLogin

from pymongo import MongoClient
from jose import JWTError, jwt
import bcrypt
from datetime import datetime, timedelta
from fastapi.middleware.cors import CORSMiddleware
from models import InstitutionRegister
app = FastAPI()
from fastapi import Depends, Request
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from fastapi import Body
from bson import ObjectId
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pymongo import MongoClient
import certifi
from models import LocationUpdate
from geopy.distance import geodesic
from fastapi import Form

# Add this AFTER app initialization
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Or replace with your frontend URL in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/superadmin/login")
# MongoDB setup
client = MongoClient(
    "mongodb+srv://tatira6301:SmartBus@cluster0.ryrrub5.mongodb.net/SmartBus?retryWrites=true&w=majority",
    tls=True,
    tlsCAFile=certifi.where()
)


db = client["SmartBus"]
superadmin_collection = db["superadmin"]
institutions_collection = db["institutions"]
admins_collection = db["admins"]

# JWT config
SECRET_KEY = "aB7fK9xQ2vLmN8zT4rG5wPoC1sYeHdJqZlU6tIbEcXvWnAuSyMzRpBgJoTqKhLfD"  # Use a secure, private key in production
ALGORITHM = "HS256"
auth_scheme = HTTPBearer()
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours

STUDENT_SECRET_KEY = "4f3b9c7d2eac8129fa0567b318e64da249cd3b7f8123efb9ae10fc98d6a1b0e73"  # Change this in production
ALGORITHM = "HS256"
student_auth_scheme = HTTPBearer()


# Utility: create JWT token
def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_superadmin(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("role") != "superadmin":
            raise HTTPException(status_code=403, detail="Not authorized")
        return payload  # you can access payload["sub"] for email
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
# ✅ Registration Endpoint
@app.post("/superadmin/register")
async def register_super_admin(data: SuperAdminRegister):
    if superadmin_collection.find_one({"email": data.email}):
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_pw = bcrypt.hashpw(data.password.encode('utf-8'), bcrypt.gensalt())

    superadmin_collection.insert_one({
        "email": data.email,
        "password": hashed_pw.decode('utf-8')
    })

    return {"message": "Super admin registered successfully"}

# ✅ Login Endpoint
@app.post("/superadmin/login")
async def login_super_admin(form_data: OAuth2PasswordRequestForm = Depends()):
    user = superadmin_collection.find_one({"email": form_data.username})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not bcrypt.checkpw(form_data.password.encode('utf-8'), user['password'].encode('utf-8')):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token_data = {
        "sub": user["email"],
        "role": "superadmin"
    }

    access_token = create_access_token(token_data, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {
        "access_token": access_token,
        "token_type": "bearer"
    }

@app.post("/institution/register")
async def register_institution( data: InstitutionRegister,
    superadmin: dict = Depends(get_current_superadmin)):
    # Check if email already exists in admins
    if admins_collection.find_one({"email": data.email}):
        raise HTTPException(status_code=400, detail="Email already registered")

    # Save to institutions (excluding password)
    institution_data = {
        "name": data.name,
        "institutionCode": data.institutionCode,
        "email": data.email,
        "mobile": data.mobile,
        "address": data.address
    }
    institutions_collection.insert_one(institution_data)

    # Hash and save to admins
    hashed_pw = bcrypt.hashpw(data.password.encode('utf-8'), bcrypt.gensalt())
    admins_collection.insert_one({
    "email": data.email,
    "password": hashed_pw.decode('utf-8'),
    "institutionCode": data.institutionCode  # ✅ Add this
})

    return {"message": "Institution registered successfully"}


@app.get("/institutions")
async def get_all_institutions():
    institutions = list(institutions_collection.find({}, {"_id": 0}))  # exclude _id
    return institutions


@app.put("/institution/{email}")
async def update_institution(
    email: str,
    updated_data: dict = Body(...),
    superadmin: dict = Depends(get_current_superadmin)
):
    # Update institutions collection
    institution_update = {
        "name": updated_data["name"],
        "institutionCode": updated_data["institutionCode"],
        "email": updated_data["email"],
        "mobile": updated_data["mobile"],
        "address": updated_data["address"]
    }

    institutions_collection.update_one(
        {"email": email},
        {"$set": institution_update}
    )

    # Update admins collection
    admin_update = {
        "email": updated_data["email"],
        "institutionCode": updated_data["institutionCode"]
    }

    if updated_data.get("password"):
        hashed_pw = bcrypt.hashpw(updated_data["password"].encode('utf-8'), bcrypt.gensalt())
        admin_update["password"] = hashed_pw.decode('utf-8')

    admins_collection.update_one(
        {"email": email},
        {"$set": admin_update}
    )

    return {"message": "Institution updated successfully"}


@app.delete("/institution/{email}")
async def delete_institution(
    email: str,
    superadmin: dict = Depends(get_current_superadmin)
):
    institutions_collection.delete_one({"email": email})
    admins_collection.delete_one({"email": email})
    return {"message": "Institution deleted successfully"}


from bson import ObjectId

@app.post("/driver/register")
async def register_driver(
    data: DriverRegister,
    superadmin: dict = Depends(get_current_superadmin)
):
    if db["drivers"].find_one({"email": data.email}):
        raise HTTPException(status_code=400, detail="Driver with this email already exists")

    hashed_pw = bcrypt.hashpw(data.password.encode('utf-8'), bcrypt.gensalt())

    # Insert driver into 'drivers' collection
    result = db["drivers"].insert_one({
    "institutionCode": data.institutionCode,
    "name": data.name,
    "email": data.email,
    "mobile": data.mobile,
    "licenseNo": data.licenseNo,
    "address": data.address,
    "password": hashed_pw.decode('utf-8'),
    "status": False,  # Driver is initially offline
    "location": {
        "latitude": None,
        "longitude": None
    }
})


    # Add driver reference to corresponding institution
    db["institutions"].update_one(
        {"institutionCode": data.institutionCode},
        {"$push": {
            "drivers": {
                "driverId": str(result.inserted_id),
                "name": data.name
            }
        }}
    )

    return {"message": "Driver registered successfully"}


@app.get("/drivers")
async def get_all_drivers():
    drivers = list(db["drivers"].find({}, {"_id": 0, "password": 0}))  # Exclude password and _id
    return drivers


@app.put("/driver/{email}")
async def update_driver(
    email: str,
    updated_data: dict,
    superadmin: dict = Depends(get_current_superadmin)
):
    # Step 1: Fetch original driver
    driver = db["drivers"].find_one({"email": email})
    if not driver:
        raise HTTPException(status_code=404, detail="Driver not found")

    # Step 2: Prepare update data
    driver_update = {
        "institutionCode": updated_data["institutionCode"],
        "name": updated_data["name"],
        "email": updated_data["email"],
        "mobile": updated_data["mobile"],
        "licenseNo": updated_data["licenseNo"],
        "address": updated_data["address"]
    }

    if updated_data.get("password"):
        hashed_pw = bcrypt.hashpw(updated_data["password"].encode('utf-8'), bcrypt.gensalt())
        driver_update["password"] = hashed_pw.decode('utf-8')

    # Step 3: Update driver document
    db["drivers"].update_one({"email": email}, {"$set": driver_update})

    # Step 4: Remove driver reference from all institutions
    db["institutions"].update_many(
        {},
        {"$pull": {"drivers": {"driverId": str(driver["_id"])}}}
    )

    # Step 5: Add driver reference to new institution
    db["institutions"].update_one(
        {"institutionCode": updated_data["institutionCode"]},
        {"$push": {
            "drivers": {
                "driverId": str(driver["_id"]),
                "name": updated_data["name"]
            }
        }}
    )

    return {"message": "Driver updated successfully"}


@app.delete("/driver/{email}")
async def delete_driver(
    email: str,
    superadmin: dict = Depends(get_current_superadmin)
):
    # Step 1: Find the driver
    driver = db["drivers"].find_one({"email": email})
    if not driver:
        raise HTTPException(status_code=404, detail="Driver not found")

    # Step 2: Delete from drivers collection
    db["drivers"].delete_one({"email": email})

    # Step 3: Remove driver reference from institution
    db["institutions"].update_many(
        {},
        {"$pull": {"drivers": {"driverId": str(driver["_id"])}}}
    )

    return {"message": "Driver deleted successfully"}


# JWT decode utility
def get_current_superadmin(token: HTTPAuthorizationCredentials = Depends(auth_scheme)):
    try:
        payload = jwt.decode(token.credentials, SECRET_KEY, algorithms=["HS256"])
        if not payload.get("role") == "superadmin":
            raise HTTPException(status_code=403, detail="Not authorized")
        return payload
    except jwt.PyJWTError:
        raise HTTPException(status_code=403, detail="Invalid token")

@app.post("/bus/register")
def register_bus(data: dict, user=Depends(get_current_superadmin)):
    institution_code = data.get("institutionCode")
    institution = db.institutions.find_one({"institutionCode": institution_code})

    if not institution:
        raise HTTPException(status_code=404, detail="Institution not found")

    bus_data = {
        "busNo": data.get("busNo"),
        "model": data.get("model"),
        "color": data.get("color"),
        "vehicleNo": data.get("vehicleNo"),
        "fuelType": data.get("fuelType"),
        "fuelCapacity": data.get("fuelCapacity"),
        "mileage": data.get("mileage"),
        "seatingCapacity": data.get("seatingCapacity"),
        "journeys": []
    }

    for j_index, journey in enumerate(data.get("journeys", []), start=1):
        driver = db.drivers.find_one({
            "institutionCode": institution_code,
            "name": journey.get("driverName")
        })

        if not driver:
            raise HTTPException(status_code=404, detail=f"Driver '{journey.get('driverName')}' not found")

        journey_obj = {
            "sequence": j_index,
            "routeName": journey.get("routeName"),
            "driverId": str(driver["_id"]),
            "startLocation": journey.get("startLocation"),
            "endLocation": journey.get("endLocation"),
            "startTime": journey.get("startTime"),
            "endTime": journey.get("endTime"),
            "totalDistance": journey.get("totalDistance"),
            "stoppages": []
        }

        for s_index, stop in enumerate(journey.get("stoppages", []), start=1):
            journey_obj["stoppages"].append({
                "sequence": s_index,
                "name": stop.get("name"),
                "latitude": stop.get("latitude"),
                "longitude": stop.get("longitude"),
                "arrivalTime": stop.get("arrivalTime")
            })

        bus_data["journeys"].append(journey_obj)

    # Save bus in institution document
    db.institutions.update_one(
        {"institutionCode": institution_code},
        {"$push": {"buses": bus_data}}
    )

    return {"message": "Bus registered successfully"}


@app.post("/student/register")
async def register_student(
    data: StudentRegister,
    superadmin: dict = Depends(get_current_superadmin)
):
    # Check if student already exists
    existing = db["students"].find_one({
        "institutionCode": data.institutionCode,
        "rollNo": data.rollNo
    })
    if existing:
        raise HTTPException(status_code=400, detail="Student already exists")

    # Insert student with full journey data
    db["students"].insert_one({
        "institutionCode": data.institutionCode,
        "institutionName": data.institutionName,
        "busNo": data.busNo,
        "rollNo": data.rollNo,
        "journeys": [journey.dict() for journey in data.journeys]
    })

    return {"message": "Student registered successfully"}



@app.post("/student/login")
def login_student(data: StudentLogin):
    student = db["students"].find_one({
        "institutionCode": data.institutionCode,
        "rollNo": data.rollNo
    })

    if not student:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    token_data = {
        "sub": student["rollNo"],
        "institutionCode": student["institutionCode"],
        "role": "student"
    }

    access_token = jwt.encode(token_data, STUDENT_SECRET_KEY, algorithm=ALGORITHM)

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "student": {
            "institutionCode": student["institutionCode"],
            "institutionName": student["institutionName"],
            "rollNo": student["rollNo"],
            "busNo": student["busNo"],
            "journeys": student.get("journeys", [])
        }
    }


def get_current_student(token: HTTPAuthorizationCredentials = Depends(student_auth_scheme)):
    try:
        payload = jwt.decode(token.credentials, STUDENT_SECRET_KEY, algorithms=["HS256"])

        if payload.get("role") != "student":
            raise HTTPException(status_code=403, detail="Not a student")
        return payload  # contains student ID or rollNo
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    


@app.post("/student/profile")
def save_student_profile(
    data: StudentProfile,
    student: dict = Depends(get_current_student)
):
    roll_no = student.get("sub")
    institution_code = student.get("institutionCode")

    if not roll_no or not institution_code:
        raise HTTPException(status_code=400, detail="Invalid token")

    update_data = {
        "name": data.name,
        "email": data.email,
        "mobile": data.mobile,
        "address": data.address
    }

    if data.password:
        hashed_pw = bcrypt.hashpw(data.password.encode('utf-8'), bcrypt.gensalt())
        update_data["password"] = hashed_pw.decode('utf-8')  # ✅ Save hashed password

    result = db["students"].update_one(
        {"institutionCode": institution_code, "rollNo": roll_no},
        {"$set": update_data}
    )

    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Student not found or no update")

    return {"message": "Student profile saved successfully"}


@app.post("/driver/login")
def login_driver(form_data: OAuth2PasswordRequestForm = Depends()):
    driver = db["drivers"].find_one({"email": form_data.username})
    if not driver or not bcrypt.checkpw(form_data.password.encode('utf-8'), driver["password"].encode('utf-8')):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    driver_id = str(driver["_id"])
    db["drivers"].update_one({"_id": driver["_id"]}, {"$set": {"status": True}})

    # ✅ Find the bus assigned to this driver
    bus_entry = db["institutions"].find_one(
        {"buses.journeys.driverId": driver_id},
        {"buses": 1}
    )

    driver_bus_no = None
    if bus_entry:
        for bus in bus_entry.get("buses", []):
            for journey in bus.get("journeys", []):
                if journey.get("driverId") == driver_id:
                    driver_bus_no = bus.get("busNo")
                    break
            if driver_bus_no:
                break

    token_data = {
        "sub": driver["email"],
        "role": "driver"
    }

    access_token = jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "driver": {
            "name": driver["name"],
            "email": driver["email"],
            "mobile": driver["mobile"],
            "institutionCode": driver["institutionCode"],
            "licenseNo": driver["licenseNo"],  # ✅ Added
            "status": driver["status"],
            "location": driver["location"],
            "busNo": driver_bus_no  # ✅ Added
        }
    }


def get_current_driver(token: HTTPAuthorizationCredentials = Depends(auth_scheme)):
    try:
        payload = jwt.decode(token.credentials, SECRET_KEY, algorithms=["HS256"])
        if payload.get("role") != "driver":
            raise HTTPException(status_code=403, detail="Not a driver")
        return payload
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


@app.get("/driver/me")
def get_driver_profile(driver_token: dict = Depends(get_current_driver)):
    email = driver_token.get("sub")
    driver = db["drivers"].find_one({"email": email}, {"password": 0})  # exclude password

    if not driver:
        raise HTTPException(status_code=404, detail="Driver not found")

    return driver


from models import LocationUpdate

from fastapi import HTTPException
from geopy.distance import geodesic

@app.post("/driver/update-location")
def update_driver_location(
    location: LocationUpdate,
    driver: dict = Depends(get_current_driver)
):
    print("🔒 Token payload:", driver)
    print("📍 Location received:", location.dict())

    email = driver.get("sub")
    if not email:
        print("❌ Missing email in token")
        raise HTTPException(status_code=400, detail="Invalid token")

    # Update driver's current location
    result = db["drivers"].update_one(
        {"email": email},
        {"$set": {
            "location.latitude": location.latitude,
            "location.longitude": location.longitude
        }}
    )

    print(f"📦 MongoDB Update result: matched={result.matched_count}, modified={result.modified_count}")

    # Fetch driver document again to access journey
    driver_doc = db["drivers"].find_one({"email": email})
    ongoing = driver_doc.get("ongoingJourney")

    if ongoing:
        stops = ongoing.get("stops", [])
        updated = False

        for i, stop in enumerate(stops):
            if not stop.get("status"):
                stop_coords = (stop["latitude"], stop["longitude"])
                driver_coords = (location.latitude, location.longitude)
                distance = geodesic(driver_coords, stop_coords).meters

                if distance < 50:  # within 50 meters
                    stops[i]["status"] = True
                    updated = True
                    print(f"🟢 Stop '{stop['name']}' marked as reached.")
                    break  # mark only one stop at a time

        if updated:
            db["drivers"].update_one(
                {"email": email},
                {"$set": {"ongoingJourney.stops": stops}}
            )

    return {"message": "Location updated successfully"}

@app.get("/driver/upcoming-journey")
async def get_upcoming_journey(driver: dict = Depends(get_current_driver)):
    now = datetime.now()
    driver_email = driver.get("sub")

    driver_doc = db["drivers"].find_one({"email": driver_email})
    if not driver_doc:
        raise HTTPException(status_code=404, detail="Driver not found")

    driver_id = str(driver_doc["_id"])

    # 🔍 Find the bus containing journeys for this driver
    institution = db["institutions"].find_one({
        "buses.journeys.driverId": driver_id
    })

    if not institution:
        return {"routeName": "No journey scheduled"}

    upcoming_journey = None
    earliest_start = None

    for bus in institution.get("buses", []):
        for journey in bus.get("journeys", []):
            if journey.get("driverId") == driver_id:
                try:
                    start_time = datetime.strptime(journey["startTime"], "%H:%M").replace(
                        year=now.year, month=now.month, day=now.day
                    )
                    end_time = datetime.strptime(journey["endTime"], "%H:%M").replace(
                        year=now.year, month=now.month, day=now.day
                    )
                except Exception as e:
                    continue

                # ⏰ Show ongoing or next journey
                if start_time <= now <= end_time:
                    return {"routeName": journey["routeName"]}
                elif now < start_time:
                    if earliest_start is None or start_time < earliest_start:
                        upcoming_journey = journey
                        earliest_start = start_time

    if upcoming_journey:
        return {"routeName": upcoming_journey["routeName"]}
    else:
        return {"routeName": "No journey scheduled"}




@app.get("/driver/next-stop")
def get_next_stop(driver: dict = Depends(get_current_driver)):
    email = driver["sub"]
    driver_data = db["drivers"].find_one({"email": email})
    if not driver_data:
        raise HTTPException(status_code=404, detail="Driver not found")

    location = driver_data.get("location", {})
    if not location.get("latitude") or not location.get("longitude"):
        raise HTTPException(status_code=400, detail="Location not available")

    driver_id = str(driver_data["_id"])

    institution = db["institutions"].find_one({
        "buses.journeys.driverId": driver_id
    })

    if not institution:
        raise HTTPException(status_code=404, detail="No bus or journey found for driver")

    next_stop = None
    for bus in institution.get("buses", []):
        for journey in bus.get("journeys", []):
            if journey.get("driverId") != driver_id:
                continue

            for stop in journey.get("stoppages", []):
                stop_loc = (stop["latitude"], stop["longitude"])
                driver_loc = (location["latitude"], location["longitude"])
                distance = geodesic(driver_loc, stop_loc).meters

                if distance > 50:  # if driver hasn't reached this stop yet
                    next_stop = stop["name"]
                    break

            if next_stop:
                break
        if next_stop:
            break

    if not next_stop:
        return {"nextStop": "Journey Completed"}
    return {"nextStop": next_stop}

@app.get("/driver/journeys")
def get_driver_journeys(driver: dict = Depends(get_current_driver)):
    email = driver["sub"]
    driver_doc = db["drivers"].find_one({"email": email})
    if not driver_doc:
        raise HTTPException(status_code=404, detail="Driver not found")

    driver_id = str(driver_doc["_id"])

    journeys = []
    institution = db["institutions"].find_one({
        "buses.journeys.driverId": driver_id
    })

    if not institution:
        return []

    for bus in institution.get("buses", []):
        for journey in bus.get("journeys", []):
            if journey["driverId"] == driver_id:
                journeys.append({
                    "routeName": journey["routeName"],
                    "stoppages": journey.get("stoppages", [])
                })

    return journeys


from fastapi import Request

@app.post("/driver/start-journey")
async def start_journey(request: Request, driver_token: dict = Depends(get_current_driver)):
    data = await request.json()
    route_name = data.get("routeName")
    driver_email = driver_token["sub"]

    # Fetch driver
    driver = db["drivers"].find_one({"email": driver_email})
    if not driver:
        raise HTTPException(status_code=404, detail="Driver not found")

    driver_id = str(driver["_id"])

    # Find assigned journey
    institution = db["institutions"].find_one({"buses.journeys.driverId": driver_id})
    if not institution:
        raise HTTPException(status_code=404, detail="No journey found")

    for bus in institution["buses"]:
        for journey in bus["journeys"]:
            if journey["driverId"] == driver_id and journey["routeName"] == route_name:
                stops = [{"name": s["name"], "status": False} for s in journey["stoppages"]]
                db["drivers"].update_one(
                    {"email": driver_email},
                    {"$set": {"ongoingJourney": {"routeName": route_name, "stoppages": stops}}}
                )
                return {"message": "Journey started"}
    raise HTTPException(status_code=404, detail="Matching journey not found")


@app.post("/driver/stop-journey")
def stop_journey(driver_token: dict = Depends(get_current_driver)):
    driver_email = driver_token["sub"]
    db["drivers"].update_one({"email": driver_email}, {"$unset": {"ongoingJourney": ""}})
    return {"message": "Journey stopped"}


@app.post("/driver/logout")
def logout_driver(driver: dict = Depends(get_current_driver)):
    email = driver.get("sub")
    if not email:
        raise HTTPException(status_code=400, detail="Invalid token")

    db["drivers"].update_one(
        {"email": email},
        {"$set": {
            "status": False,
            "location.latitude": None,
            "location.longitude": None
        }}
    )
    return {"message": "Logout successful"}


@app.post("/admin/login")
async def login_admin(form_data: OAuth2PasswordRequestForm = Depends()):
    admin = admins_collection.find_one({"email": form_data.username})
    if not admin:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not bcrypt.checkpw(form_data.password.encode('utf-8'), admin["password"].encode('utf-8')):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token_data = {
        "sub": admin["email"],
        "role": "admin"
    }

    access_token = create_access_token(token_data, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "admin": {
            "email": admin["email"],
            "institutionCode": admin.get("institutionCode", "")
        }
    }


def get_current_admin(token: HTTPAuthorizationCredentials = Depends(auth_scheme)):
    try:
        payload = jwt.decode(token.credentials, SECRET_KEY, algorithms=["HS256"])
        if payload.get("role") != "admin":
            raise HTTPException(status_code=403, detail="Not an admin")
        return payload
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


@app.get("/admin/dashboard")
def get_admin_dashboard(admin: dict = Depends(get_current_admin)):
    return {"message": f"Welcome {admin['sub']}"}


@app.get("/admin/buses")
def get_admin_buses(token: HTTPAuthorizationCredentials = Depends(auth_scheme)):
    payload = jwt.decode(token.credentials, SECRET_KEY, algorithms=["HS256"])

    if not payload or payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Invalid or unauthorized token")

    email = payload.get("sub")  # we store email under "sub"
    if not email:
        raise HTTPException(status_code=400, detail="Token missing email")

    admin = db["admins"].find_one({"email": email})
    if not admin:
        raise HTTPException(status_code=404, detail="Admin not found")

    institution_code = admin.get("institutionCode")
    if not institution_code:
        raise HTTPException(status_code=400, detail="Admin has no institutionCode")

    institution = db["institutions"].find_one({"institutionCode": institution_code})
    if not institution:
        raise HTTPException(status_code=404, detail="Institution not found")

    bus_list = institution.get("buses", [])

    result = []
    for bus in bus_list:
        # You can customize how status, currentJourney, and location are fetched
        result.append({
            "busNo": bus.get("busNo", ""),
            "vehicleNo": bus.get("vehicleNo", ""),
            "status": "Active" if any(driver.get("status") for driver in db["drivers"].find({"institutionCode": institution_code})) else "Offline",
            "currentJourney": next((j["routeName"] for j in bus.get("journeys", []) if j["driverId"] in [str(d["_id"]) for d in db["drivers"].find({"institutionCode": institution_code, "status": True})]), "None"),
            "location": next((f"{d.get('location', {}).get('latitude', 0)},{d.get('location', {}).get('longitude', 0)}" for d in db["drivers"].find({"institutionCode": institution_code, "status": True})), "Unknown")
        })

    return result


@app.post("/student/verify-enrollment")
def verify_enrollment(data: dict = Body(...)):
    institution_code = data.get("institution_code")
    enrollment = data.get("enrollment")

    if not institution_code or not enrollment:
        raise HTTPException(status_code=400, detail="Missing institution_code or enrollment")

    student = db["students"].find_one({
        "institutionCode": institution_code,
        "rollNo": enrollment
    })

    if student:
        token_data = {
            "sub": enrollment,
            "institutionCode": institution_code,
            "role": "student-unregistered"
        }
        token = jwt.encode(token_data, STUDENT_SECRET_KEY, algorithm=ALGORITHM)
        return {"message": "Enrollment verified", "access_token": token}
    else:
        raise HTTPException(status_code=404, detail="Student not found")


@app.post("/student/complete-registration")
def complete_student_registration(
    data: StudentProfile,
    token: HTTPAuthorizationCredentials = Depends(student_auth_scheme)
):
    try:
        payload = jwt.decode(token.credentials, STUDENT_SECRET_KEY, algorithms=["HS256"])
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    if payload.get("role") != "student-unregistered":
        raise HTTPException(status_code=403, detail="Invalid token role")

    roll_no = payload.get("sub")
    institution_code = payload.get("institutionCode")

    if not roll_no or not institution_code:
        raise HTTPException(status_code=400, detail="Invalid token payload")

    hashed_pw = bcrypt.hashpw(data.password.encode('utf-8'), bcrypt.gensalt())

    result = db["students"].update_one(
        {"institutionCode": institution_code, "rollNo": roll_no},
        {"$set": {
            "name": data.name,
            "email": data.email,
            "mobile": data.mobile,
            "address": data.address,
            "password": hashed_pw.decode('utf-8')
        }}
    )

    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Student not found or already registered")

    return {"message": "Student registered successfully"}


@app.post("/student/login-secure")
def secure_login_student(data: StudentSecureLogin):
    student = db["students"].find_one({
        "institutionCode": data.institutionCode,
        "email": data.email
    })

    if not student:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or institution code")

    if not bcrypt.checkpw(data.password.encode('utf-8'), student.get("password", "").encode('utf-8')):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password")

    token_data = {
        "sub": student["email"],
        "institutionCode": student["institutionCode"],
        "role": "student"
    }

    access_token = jwt.encode(token_data, STUDENT_SECRET_KEY, algorithm=ALGORITHM)

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "student": {
            "institutionCode": student["institutionCode"],
            "institutionName": student["institutionName"],
            "rollNo": student["rollNo"],
            "busNo": student["busNo"],
            "journeys": student.get("journeys", [])
        }
    }



# main.py
from fastapi import Depends
from bson import ObjectId
@app.get("/student/bus-status")
async def get_bus_status(bus_no: str, institution_code: str):
    # Step 1: Find active driver for this bus
    active_driver = db["drivers"].find_one({
        "institutionCode": institution_code,
        "status": True
    })

    if not active_driver:
        return {"active": False}

    driver_id = str(active_driver["_id"])

    # Step 2: Find institution and match bus and journey
    institution = db["institutions"].find_one({"institutionCode": institution_code})
    if not institution:
        return {"active": False}

    for bus in institution.get("buses", []):
        if bus.get("busNo") == bus_no:
            for journey in bus.get("journeys", []):
                if journey.get("driverId") == driver_id:
                    return {
                        "active": True,
                        "mobile": active_driver["mobile"],
                        "journey": journey["routeName"]
                    }

    return {"active": False}


from datetime import datetime

@app.get("/student/stops")
def get_stops_for_student(student: dict = Depends(get_current_student)):
    roll_no = student.get("sub")
    institution_code = student.get("institutionCode")

    # Get student document
    student_doc = db["students"].find_one({"institutionCode": institution_code, "rollNo": roll_no})
    if not student_doc:
        raise HTTPException(status_code=404, detail="Student not found")

    bus_no = student_doc.get("busNo")
    if not bus_no:
        raise HTTPException(status_code=404, detail="No bus assigned")

    # Find active driver for this bus
    active_driver = db["drivers"].find_one({
        "institutionCode": institution_code,
        "status": True
    })
    if not active_driver:
        raise HTTPException(status_code=404, detail="Bus not active")

    driver_location = active_driver.get("location", {})
    if not driver_location.get("latitude") or not driver_location.get("longitude"):
        raise HTTPException(status_code=400, detail="Driver location unavailable")

    driver_id = str(active_driver["_id"])
    institution = db["institutions"].find_one({"institutionCode": institution_code})

    for bus in institution.get("buses", []):
        if bus.get("busNo") == bus_no:
            for journey in bus.get("journeys", []):
                if journey.get("driverId") == driver_id:
                    stoppages = journey.get("stoppages", [])

                    # Estimate arrival time based on avg speed = 25 km/h (6.94 m/s)
                    avg_speed = 6.94  # meters/sec
                    from geopy.distance import geodesic

                    stops_with_eta = []
                    now = datetime.now()
                    driver_coords = (driver_location["latitude"], driver_location["longitude"])

                    for stop in stoppages:
                        stop_coords = (stop["latitude"], stop["longitude"])
                        dist = geodesic(driver_coords, stop_coords).meters
                        eta_secs = int(dist / avg_speed)
                        eta_time = (now + timedelta(seconds=eta_secs)).strftime("%H:%M")
                        diff_minutes = eta_secs // 60

                        stops_with_eta.append({
                            "name": stop["name"],
                            "defaultArrivalTime": stop["arrivalTime"],
                            "estimatedArrivalTime": eta_time,
                            "inMinutes": diff_minutes
                        })

                    return stops_with_eta

    raise HTTPException(status_code=404, detail="No journey found for active driver")
