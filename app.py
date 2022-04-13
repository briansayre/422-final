#!flask/bin/python
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

SALE_CATEGORIES = ["cars", "motorcycles", "boats", "books", "furniture"]
HOUSING_CATEGORIES = ["house", "apartment", "condo", "hotel", "vacation"]
JOBS_CATEGORIES = ["accounting", "education", "security", "labor", "transport"]
COMMUNITY_CATEGORIES = ["art", "lostandfound", "groups", "classes", "pets"]
SERVICES_CATEGORIES = ["cleaning", "plumbing",
                       "electrical", "computer", "legal"]

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
        response = user_table.scan(
            FilterExpression=Attr('username').eq(str(username))
        )
        items = response['Items']
        response_password = items[0]['password']
        if (password == response_password):
            session['user_id'] = items[0]['userid']
            session['username'] = items[0]['username']
            return redirect('/')
        return redirect('/')
    return render_template('login.html')


@app.route('/logout')
def logout():
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
            if category in SALE_CATEGORIES:
                sale_table.put_item(Item=item)
            elif category in HOUSING_CATEGORIES:
                housing_table.put_item(Item=item)
            elif category in SERVICES_CATEGORIES:
                services_table.put_item(Item=item)
            elif category in JOBS_CATEGORIES:
                jobs_table.put_item(Item=item)
            elif category in COMMUNITY_CATEGORIES:
                community_table.put_item(Item=item)
            return redirect('/')
        else:
            return render_template('add.html')
    else:
        return redirect("/")


@app.route('/delete', methods=['POST'])
def delete_posts():
    id = request.args.get('id', None)
    category = request.args.get('category', None)
    if id and category:
        post = get_posts_by_id(id)[0]
        if post["username"] == session.get("username"):
            if category in SALE_CATEGORIES:
                sale_table.delete_item(Key={"id":id})
            elif category in HOUSING_CATEGORIES:
                housing_table.delete_item(Key={"id":id})
            elif category in SERVICES_CATEGORIES:
                services_table.delete_item(Key={"id":id})
            elif category in JOBS_CATEGORIES:
                jobs_table.delete_item(Key={"id":id})
            elif category in COMMUNITY_CATEGORIES:
                community_table.delete_item(Key={"id":id})
    return redirect("/posts?userid="+session.get("user_id"))

@app.route('/search', methods=['GET'])
def search_posts():
    query = request.args.get('query', None)
    items = []
    filter_exp = (Attr('title').contains(str(query)) |
                  Attr('description').contains(str(query)) |
                  Attr('category').contains(str(query)) |
                  Attr('contact').contains(str(query)) |
                  Attr('location').contains(str(query)) |
                  Attr('username').contains(str(query)))
    response = sale_table.scan(FilterExpression=filter_exp)
    if (response['Items']):
        items.extend(response['Items'])
    response = housing_table.scan(FilterExpression=filter_exp)
    if (response['Items']):
        items.extend(response['Items'])
    response = services_table.scan(FilterExpression=filter_exp)
    if (response['Items']):
        items.extend(response['Items'])
    response = jobs_table.scan(FilterExpression=filter_exp)
    if (response['Items']):
        items.extend(response['Items'])
    response = community_table.scan(FilterExpression=filter_exp)
    if (response['Items']):
        items.extend(response['Items'])
    return render_template('posts.html', posts=items, category="Search results for: " + query)


@app.route('/posts', methods=['GET'])
def view_posts():
    id = request.args.get('id', None)
    userid = request.args.get('userid', None)
    section = request.args.get('section', None)
    category = request.args.get('category', None)
    if id:
        return render_template('posts.html', posts=get_posts_by_id(id), category="Post with ID: " + id)
    elif userid:
        return render_template('posts.html', posts=get_posts_by_userid(userid), category="Posts made by user: " + get_username(userid).capitalize())
    elif section:
        return render_template('posts.html', posts=get_posts_by_section(section), category="Posts in section: " + section.capitalize())
    elif category:
        return render_template('posts.html', posts=get_posts_by_category(category), category="Posts in category: " + category.capitalize())
    return redirect("/")


def get_posts_by_id(id):
    response = sale_table.scan(FilterExpression=Key('id').eq(str(id)))
    if (response['Items']):
        return response["Items"]
    response = housing_table.scan(FilterExpression=Key('id').eq(str(id)))
    if (response['Items']):
        return response["Items"]
    response = services_table.scan(FilterExpression=Key('id').eq(str(id)))
    if (response['Items']):
        return response["Items"]
    response = jobs_table.scan(FilterExpression=Key('id').eq(str(id)))
    if (response['Items']):
        return response["Items"]
    response = community_table.scan(FilterExpression=Key('id').eq(str(id)))
    if (response['Items']):
        return response["Items"]
    return {}


def get_posts_by_userid(userid):
    items = []
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
    return items


def get_username(userid):
    response = user_table.scan(
        FilterExpression=(Key('userid').eq(str(userid))))
    return response['Items'][0]['username']


def get_posts_by_section(section):
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
    return response["Items"]


def get_posts_by_category(category):
    if category in SALE_CATEGORIES:
        response = sale_table.scan(
            FilterExpression=Attr('category').eq(str(category)))
    elif category in HOUSING_CATEGORIES:
        response = housing_table.scan(
            FilterExpression=Attr('category').eq(str(category)))
    elif category in SERVICES_CATEGORIES:
        response = services_table.scan(
            FilterExpression=Attr('category').eq(str(category)))
    elif category in JOBS_CATEGORIES:
        response = jobs_table.scan(
            FilterExpression=Attr('category').eq(str(category)))
    elif category in COMMUNITY_CATEGORIES:
        response = community_table.scan(
            FilterExpression=Attr('category').eq(str(category)))
    else:
        response = {'Items': []}
    return response['Items']


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)
