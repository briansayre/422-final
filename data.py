from pydoc import describe
from unicodedata import category
from flask import Flask, jsonify, request, make_response
from flask import render_template, redirect, session
import boto3
import random
import names
from boto3.dynamodb.conditions import Key, Attr

app = Flask(__name__)
app.secret_key = 'whoop'

AWS_ACCESS_KEY = "AKIA2TPIYF2FIK7EZE6Z"
AWS_SECRET_KEY = "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"
REGION = "us-east-1"

category = [
    "cars", "motorcycles", "boats", "books", "furniture",
    "house", "apartment", "condo", "hotel", "vacation",
    "cleaning", "plumbing", "electrical", "computer", "legal",
    "accounting", "education", "security", "labor", "transport",
    "art", "lostandfound", "groups", "classes", "pets"
]
title = [
    "Ea nostrud non veniam",
    "Et commodo amet ",
    "Aliquip adipisic",
    "Amet  culpa irure ",
    "Aliqua esse aute aliquip sint esse officia ",
    "Ex reprehenderit duis aliquip ",
    "Ad laboris ",
    "Esse et duis et laboris sunt cillum ",
    "Deserunt minim  cillum sunt ",
    "Velit exercitation ea ",
    "Consectetur qui eu sunt dolore ",
    "Laboris laborum adipisicing ",
    "Lorem cupidatat laboris velit esse non ",
    "Do sunt sint magna ",
    "Cupidatat ullamco",
    "In nisi esse",
    "Do commodo aliquip",
    "Et culpa excepteur",
    "Tempor quis ex ipsum",
    "Dolor ad anim",
    "Culpa enim adipisicingcupidatat",
    "Ex minim ipsum duis et culpa",
    "Eiusmod aute ullamco ea elit",
    "Sunt sint veniam ad aute excepteur",
    "Laboris adipisicing",
    "Magna fugiat do",
    "Ex labore aliqua do cupidatat et",
    "Nostrud eu excepteur ut",
    "Consequat dolore consequat"
]
description = [
    "Duis magna non irure fugiat cupidatat sunt officia cupidatat et minim amet non reprehenderit amet.",
    "Exercitation in et magna ipsum ad cupidatat excepteur dolore reprehenderit culpa.",
    "Magna culpa occaecat sit laborum Lorem.",
    "Est elit enim laborum dolore nulla ipsum ut exercitation eu.",
    "Nostrud laborum mollit anim qui dolore duis officia culpa ea.",
    "Nisi excepteur nulla incididunt enim excepteur pariatur magna minim reprehenderit sint labore occaecat.",
    "Ut sit exercitation Lorem officia pariatur velit mollit nulla ex irure excepteur ea.",
    "Fugiat magna sit cupidatat esse veniam cupidatat nulla.",
    "Ut minim sit voluptate fugiat et irure aute deserunt exercitation ullamco minim eiusmod.",
    "Laboris sit excepteur eu proident.",
    "Incididunt officia excepteur incididunt labore qui pariatur nostrud irure.",
    "Sint consequat sit proident velit irure nisi id elit irure consequat ullamco consequat voluptate mollit.",
    "Dolor veniam eiusmod sunt pariatur dolore fugiat mollit exercitation irure nostrud.",
    "In id officia minim incididunt quis consequat nisi sit.",
    "Proident irure ad qui duis fugiat deserunt ex.",
    "Elit reprehenderit laboris quis nisi do.",
    "Sint consequat reprehenderit culpa et nisi duis Lorem nisi eiusmod.",
    "Lorem anim laboris irure aliquip et quis esse quis reprehenderit commodo.",
    "Ullamco consequat quis Lorem aute dolor quis.",
    "Sit commodo nisi irure veniam ullamco reprehenderit consequat eu nostrud duis.",
    "Officia dolore ad est eu duis nulla tempor dolor sit proident velit reprehenderit pariatur.",
    "Magna nulla non nulla enim cupidatat.",
    "Fugiat nulla officia commodo amet.",
    "Dolore nulla est ea sint esse et velit incididunt duis Lorem occaecat.",
    "In amet consequat eiusmod quis non exercitation excepteur id et.",
    "Id mollit ipsum deserunt voluptate Lorem ullamco fugiat non excepteur nostrud non irure eiusmod.",
    "Dolor commodo laborum Lorem veniam.",
    "Laborum nisi adipisicing eu proident Lorem Lorem cupidatat labore ipsum quis reprehenderit.",
    "Proident velit eu ipsum minim proident tempor laborum.",
    "Sunt qui excepteur laborum sunt elit aliqua fugiat.",

]

dynamodb = boto3.resource('dynamodb', aws_access_key_id=AWS_ACCESS_KEY,
                          aws_secret_access_key=AWS_SECRET_KEY,
                          region_name=REGION)
user_table = dynamodb.Table('Users')
sale_table = dynamodb.Table('ForSale')
housing_table = dynamodb.Table('Housing')
services_table = dynamodb.Table('Services')
jobs_table = dynamodb.Table('Jobs')
community_table = dynamodb.Table('Community')


def add_post(category):
    item = {
        "id": random_id(),
        "title": random_title(),
        "description": random_description(),
        "category": category,
        "contact": random_contact(),
        "location": "Ames, IA",
        "price": random_price(),
        "userid": random_id(),
        "username": random_username()
    }
    sale = ["cars", "motorcycles", "boats", "books", "furniture"]
    housing = ["house", "apartment", "condo", "hotel", "vacation"]
    services = ["cleaning", "plumbing", "electrical", "computer", "legal"]
    jobs = ["accounting", "education", "security", "labor", "transport"]
    community = ["art", "lostandfound", "groups", "classes", "pets"]
    if category in sale:
        print("sale")
        response = sale_table.put_item(Item=item)
    elif category in housing:
        print("housing")
        response = housing_table.put_item(Item=item)
    elif category in services:
        print("services")
        response = services_table.put_item(Item=item)
    elif category in jobs:
        print("jobs")
        response = jobs_table.put_item(Item=item)
    elif category in community:
        print("community")
        response = community_table.put_item(Item=item)

def random_id():
    return str(random.randint(10000, 100000))

def random_title():
    return random.choice(title)

def random_description():
    return random.choice(description)
    
def random_contact():
    return str(random.randint(100, 999))+"-"+str(random.randint(100, 999))+"-"+str(random.randint(1000, 9999))

def random_price():
    return str(random.randint(0, 10000))

def random_username():
    return names.get_full_name()

def main():
    for c in range(25):
        for i in range(15):
            add_post(category[c])

# main()
