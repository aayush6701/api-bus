from pydantic import BaseModel, EmailStr,  Field
from typing import Optional,List

class SuperAdminRegister(BaseModel):
    email: EmailStr
    password: str


class InstitutionRegister(BaseModel):
    name: str
    institutionCode: str
    email: EmailStr
    mobile: str
    address: str
    password: str


class DriverRegister(BaseModel):
    institutionCode: str
    name: str
    email: EmailStr
    mobile: str
    licenseNo: str
    address: str
    password: str
    



class JourneyData(BaseModel):
    routeName: str
    stoppage: str

class StudentRegister(BaseModel):
    institutionCode: str
    institutionName: str
    rollNo: str
    busNo: str
    journeys: List[JourneyData]

class StudentLogin(BaseModel):
    institutionCode: str
    rollNo: str

class StudentProfile(BaseModel):
    name: str
    email: str
    password: str
    mobile: str
    address: str
