from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordRequestForm
from models import SuperAdminRegister, DriverRegister, StudentRegister, StudentLogin, StudentProfile
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
            "status": driver["status"],
            "location": driver["location"]
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
