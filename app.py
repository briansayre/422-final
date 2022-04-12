'''
MIT License

Copyright (c) 2019 Arshdeep Bahga and Vijay Madisetti

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
'''

#!flask/bin/python
from unicodedata import category
from flask import Flask, jsonify, abort, request, make_response, url_for
from flask import render_template, redirect, session
import os
import boto3
import time
import datetime
from boto3.dynamodb.conditions import Key, Attr
import json

app = Flask(__name__)
app.secret_key = 'whoop'

AWS_ACCESS_KEY = "AKIA2TPIYF2FIK7EZE6Z"
AWS_SECRET_KEY = "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"
REGION = "us-east-1"

dynamodb = boto3.resource('dynamodb', aws_access_key_id=AWS_ACCESS_KEY,
                          aws_secret_access_key=AWS_SECRET_KEY,
                          region_name=REGION)


user_table = dynamodb.Table('Users')
sale_table = dynamodb.Table('ForSale')
housing_table = dynamodb.Table('Housing')
services_table = dynamodb.Table('Services')
jobs_table = dynamodb.Table('Jobs')
community_table = dynamodb.Table('Community')


@app.errorhandler(400)
def bad_request(error):
    return make_response(jsonify({'error': 'Bad request'}), 400)


@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)


@app.route('/', methods=['GET'])
def index():
    if session.get("username"):
        print(session.get("username"))
        return render_template('index.html', username=session.get("username"))
    return render_template('index.html', username="")


@app.route('/signup', methods=['POST'])
def signup():
    ts = time.time()
    username = request.form['username']
    password = request.form['password']
    if (username == "" or password == ""):
        return redirect('/')
    new_user_id = str(int(ts*1000))
    user_table.put_item(
        Item={
            "userid": new_user_id,
            "username": username,
            "password": password
        }
    )
    session["user_id"] = new_user_id
    session["username"] = username
    return redirect('/')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if (username == "" or password == ""):
            return redirect('/')
        print("u: " + username + "p: " + password)
        response = user_table.scan(
            FilterExpression=Attr('username').eq(str(username))
        )
        items = response['Items']
        response_password = items[0]['password']
        if (password == response_password):
            session['user_id'] = items[0]['userid']
            session['username'] = items[0]['username']
            print("pass=curr " + str(items[0]['userid']))
            return redirect('/')
        return redirect('/')
    return render_template('login.html')


@app.route('/logout')
def logout():
    # remove the username from the session if it is there
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect('/')


# @app.route('/home', methods=['GET', 'POST'])
# def home_page():
#     response = table.scan(FilterExpression=Attr(
#         'UserID').eq(session["user_id"]))
#     items = response['Items']
#     response2 = user_table.scan(
#         FilterExpression=Key('userid').eq(str(session["user_id"]))
#     )
#     username = response2['Items'][0]['username']
#     print(items)
#     print("USERID: " + str(session['user_id']))
#     return render_template('home.html', photos=items, name=username)


@app.route('/add', methods=['GET', 'POST'])
def add_photo():
    if request.method == 'POST':
        uploadedFileURL = ''

        title = request.form['title']
        description = request.form['description']
        category = request.form['category']
        ts = time.time()
        item = {
            "id": str(int(ts*1000)),
            "title": title,
            "description": description,
            "category": category,
            "userid": str(session['user_id'])
        }
        print(item)
        sale = ["cars", "motorcycles", "boats", "books", "furniture"]
        housing = ["house", "apartment", "condo", "hotel", "vacation"]
        services = ["cleaning", "plumbing", "electrical", "computer", "legal"]
        jobs = ["accounting", "education", "security", "labor", "transport"]
        community = ["art", "lostandfound", "groups", "classes", "pets"]

        if category in sale:
            print("sale")
            response = sale_table.scan(
                FilterExpression=Attr('category').eq(str(category)))
        elif category in housing:
            print("housing")
            response = housing_table.scan(
                FilterExpression=Attr('category').eq(str(category)))
        elif category in services:
            print("services")
            response = services_table.scan(
                FilterExpression=Attr('category').eq(str(category)))
        elif category in jobs:
            print("jobs")
            response = jobs_table.scan(
                FilterExpression=Attr('category').eq(str(category)))
        elif category in community:
            print("community")
            response = community_table.scan(
                FilterExpression=Attr('category').eq(str(category)))
        # table.put_item(
        #     Item={
        #         "PhotoID": str(int(ts*1000)),
        #         "CreationTime": timestamp,
        #         "Title": title,
        #         "Description": description,
        #         "Tags": tags,
        #         "URL": uploadedFileURL,
        #         "ExifData": json.dumps(ExifData),
        #         "UserID": str(session['user_id'])
        #     }
        # )

        return redirect('/')
    else:
        return render_template('form.html')


@app.route('/search', methods=['GET'])
def search_page():
    query = request.args.get('query', None)

    response = table.scan(
        FilterExpression=(Attr('title').contains(str(query)) |
                          Attr('description').contains(str(query)))
    )
    items = response['Items']
    return render_template('search.html',
                           photos=items, searchquery=query)


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)


@app.route('/category', methods=['GET'])
def view_category():
    category = request.args.get('category', None)
    sale = ["cars", "motorcycles", "boats", "books", "furniture"]
    housing = ["house", "apartment", "condo", "hotel", "vacation"]
    services = ["cleaning", "plumbing", "electrical", "computer", "legal"]
    jobs = ["accounting", "education", "security", "labor", "transport"]
    community = ["art", "lostandfound", "groups", "classes", "pets"]

    if category in sale:
        print("sale")
        response = sale_table.scan(
            FilterExpression=Attr('category').eq(str(category)))
    elif category in housing:
        print("housing")
        response = housing_table.scan(
            FilterExpression=Attr('category').eq(str(category)))
    elif category in services:
        print("services")
        response = services_table.scan(
            FilterExpression=Attr('category').eq(str(category)))
    elif category in jobs:
        print("jobs")
        response = jobs_table.scan(
            FilterExpression=Attr('category').eq(str(category)))
    elif category in community:
        print("community")
        response = community_table.scan(
            FilterExpression=Attr('category').eq(str(category)))
    else:
        response = {'Items': []}
    items = response['Items']
    return render_template('category.html', posts=items)


@app.route('/post', methods=['GET'])
def view_post():
    category = request.args.get('id', None)
    sale = ["cars", "motorcycles", "boats", "books", "furniture"]
    housing = ["house", "apartment", "condo", "hotel", "vacation"]
    services = ["cleaning", "plumbing", "electrical", "computer", "legal"]
    jobs = ["accounting", "education", "security", "labor", "transport"]
    community = ["art", "lostandfound", "groups", "classes", "pets"]

    if category in sale:
        print("sale")
        response = sale_table.scan(
            FilterExpression=Attr('category').eq(str(category)))
    elif category in housing:
        print("housing")
        response = housing_table.scan(
            FilterExpression=Attr('category').eq(str(category)))
    elif category in services:
        print("services")
        response = services_table.scan(
            FilterExpression=Attr('category').eq(str(category)))
    elif category in jobs:
        print("jobs")
        response = jobs_table.scan(
            FilterExpression=Attr('category').eq(str(category)))
    elif category in community:
        print("community")
        response = community_table.scan(
            FilterExpression=Attr('category').eq(str(category)))
    else:
        response = {'Items': []}
    items = response['Items']
    return render_template('category.html', posts=items)
