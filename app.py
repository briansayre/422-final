#!flask/bin/python
from unicodedata import category
from flask import Flask, jsonify, request, make_response
from flask import render_template, redirect, session
import boto3
import time
import os
from boto3.dynamodb.conditions import Key, Attr

app = Flask(__name__)
app.secret_key = 'whoop'

UPLOAD_FOLDER = os.path.join(app.root_path, 'static/media')
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg'])
AWS_ACCESS_KEY = "AKIA2TPIYF2FIK7EZE6Z"
AWS_SECRET_KEY = "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"
REGION = "us-east-1"
BUCKET_NAME = "photo-gallery-bucket-gt"

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
        return render_template('index.html', username=session.get("username").capitalize())
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


@app.route('/add', methods=['GET', 'POST'])
def add_post():
    if session.get("user_id"):
        if request.method == 'POST':
            title = request.form['title']
            description = request.form['description']
            category = request.form['category']
            location = request.form['location']
            contact = request.form['contact']
            price = request.form['price']
            ts = time.time()
            item = {
                "id": str(int(ts*1000)),
                "title": title,
                "description": description,
                "category": category,
                "contact": contact,
                "location": location,
                "price": price,
                "userid": str(session['user_id']),
                "username": str(session['username'])
            }
            print(item)
            sale = ["cars", "motorcycles", "boats", "books", "furniture"]
            housing = ["house", "apartment", "condo", "hotel", "vacation"]
            services = ["cleaning", "plumbing",
                        "electrical", "computer", "legal"]
            jobs = ["accounting", "education",
                    "security", "labor", "transport"]
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
            return redirect('/')
        else:
            return render_template('add.html')
    else:
        return redirect("/")


@app.route('/search', methods=['GET'])
def search_posts():
    query = request.args.get('query', None)
    items = []
    response = sale_table.scan(
        FilterExpression=(Attr('title').contains(str(query)) |
                          Attr('description').contains(str(query)) |
                          Attr('contact').contains(str(query)) |
                          Attr('location').contains(str(query))))
    if (response['Items']):
        items.extend(response['Items'])
    response = housing_table.scan(
        FilterExpression=(Attr('title').contains(str(query)) |
                          Attr('description').contains(str(query)) |
                          Attr('contact').contains(str(query)) |
                          Attr('location').contains(str(query))))
    if (response['Items']):
        items.extend(response['Items'])
    response = services_table.scan(
        FilterExpression=(Attr('title').contains(str(query)) |
                          Attr('description').contains(str(query)) |
                          Attr('contact').contains(str(query)) |
                          Attr('location').contains(str(query))))
    if (response['Items']):
        items.extend(response['Items'])
    response = jobs_table.scan(
        FilterExpression=(Attr('title').contains(str(query)) |
                          Attr('description').contains(str(query)) |
                          Attr('contact').contains(str(query)) |
                          Attr('location').contains(str(query))))
    if (response['Items']):
        items.extend(response['Items'])
    response = community_table.scan(
        FilterExpression=(Attr('title').contains(str(query)) |
                          Attr('description').contains(str(query)) |
                          Attr('contact').contains(str(query)) |
                          Attr('location').contains(str(query))))
    if (response['Items']):
        items.extend(response['Items'])
    print(items)
    return render_template('posts.html', posts=items, category="Search results for: " + query)


@app.route('/posts/<id>', methods=['GET'])
def view_post(id):
    response = sale_table.scan(FilterExpression=Key('id').eq(str(id)))
    if (response['Items']):
        return render_template('post.html', p=response['Items'][0], category="Post with ID: " + id)
    response = housing_table.scan(FilterExpression=Key('id').eq(str(id)))
    if (response['Items']):
        return render_template('post.html', p=response['Items'][0], category="Post with ID: " + id)
    response = services_table.scan(FilterExpression=Key('id').eq(str(id)))
    if (response['Items']):
        return render_template('post.html', p=response['Items'][0], category="Post with ID: " + id)
    response = jobs_table.scan(FilterExpression=Key('id').eq(str(id)))
    if (response['Items']):
        return render_template('post.html', p=response['Items'][0], category="Post with ID: " + id)
    response = community_table.scan(FilterExpression=Key('id').eq(str(id)))
    if (response['Items']):
        return render_template('post.html', p=response['Items'][0], category="Post with ID: " + id)
    return render_template('post.html', p={}, category="No post with ID: " + id)


@app.route('/posts', methods=['GET'])
def view_posts():
    category = request.args.get('category', None)
    section = request.args.get('section', None)
    userid = request.args.get('userid', None)

    if userid:
        items = []
        response = user_table.scan(
            FilterExpression=(Key('userid').eq(str(userid))))
        print(response)
        username = response['Items'][0]['username']

        response = sale_table.scan(
            FilterExpression=(Attr('userid').eq(str(userid))))
        if (response['Items']):
            items.extend(response['Items'])

        response = housing_table.scan(
            FilterExpression=(Attr('userid').eq(str(userid))))
        if (response['Items']):
            items.extend(response['Items'])

        response = services_table.scan(
            FilterExpression=(Attr('userid').eq(str(userid))))
        if (response['Items']):
            items.extend(response['Items'])

        response = jobs_table.scan(
            FilterExpression=(Attr('userid').eq(str(userid))))
        if (response['Items']):
            items.extend(response['Items'])

        response = community_table.scan(
            FilterExpression=(Attr('userid').eq(str(userid))))
        if (response['Items']):
            items.extend(response['Items'])

        print(items)
        return render_template('posts.html', posts=items, category="Posts for user " + username)

    elif section:
        if section == "sale":
            response = sale_table.scan()
        elif section == "housing":
            response = housing_table.scan()
        elif section == "services":
            response = services_table.scan()
        elif section == "jobs":
            response = jobs_table.scan()
        elif section == "community":
            response = community_table.scan()
        else:
            response = {'Items': []}
        return render_template('posts.html', posts=response['Items'], category="Posts for " + section.capitalize())

    elif category:

        sale = ["cars", "motorcycles", "boats", "books", "furniture"]
        housing = ["house", "apartment", "condo", "hotel", "vacation"]
        services = ["cleaning", "plumbing", "electrical", "computer", "legal"]
        jobs = ["accounting", "education", "security", "labor", "transport"]
        community = ["art", "lostandfound", "groups", "classes", "pets"]

        if category in sale:
            response = sale_table.scan(
                FilterExpression=Attr('category').eq(str(category)))
        elif category in housing:
            response = housing_table.scan(
                FilterExpression=Attr('category').eq(str(category)))
        elif category in services:
            response = services_table.scan(
                FilterExpression=Attr('category').eq(str(category)))
        elif category in jobs:
            response = jobs_table.scan(
                FilterExpression=Attr('category').eq(str(category)))
        elif category in community:
            response = community_table.scan(
                FilterExpression=Attr('category').eq(str(category)))
        else:
            response = {'Items': []}
        items = response['Items']
        return render_template('posts.html', posts=items, category="Posts for " + category.capitalize())
    return redirect("/")


def s3uploading(filename, filenameWithPath):
    s3 = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY,
                      aws_secret_access_key=AWS_SECRET_KEY)
    bucket = BUCKET_NAME
    path_filename = "photos/" + filename
    print(path_filename)
    s3.upload_file(filenameWithPath, bucket, path_filename)
    print("http://" + BUCKET_NAME + ".s3.amazonaws.com/" + path_filename)
    return "http://" + BUCKET_NAME + ".s3.amazonaws.com/" + path_filename


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)
