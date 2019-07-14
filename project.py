from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from database_setup import Base, Categories, CategoriesItem, User
from flask import session as login_session
from wtforms import Form, BooleanField, StringField, PasswordField, validators
from wtforms.validators import DataRequired, Email, URL
from flask_wtf.csrf import CsrfProtect
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

csrf = CsrfProtect()
app = Flask(__name__)
app.config['SECRET_KEY'] = '7d441f27d441f27567d441f2b6176a'
csrf.init_app(app)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "CATALOG"
#WTF_CSRF_CHECK_DEFAULT=False


# Connect to Database and create database session
engine = create_engine('sqlite:///categoriesitems.db')
Base.metadata.bind = engine

DBSession = scoped_session(sessionmaker(bind=engine))
session = DBSession()

class RegistrationForm(Form):
    name = StringField('Username', [validators.Length(min=4, max=25),validators.DataRequired()])
    email = StringField('Email Address', [validators.DataRequired(),Email()])
    picture = StringField('Picture')#[URL()]

class CatalogForm(Form):
    name = StringField('Username', [validators.Length(min=2, max=25),validators.DataRequired()])

class ItemsForm(Form):
    name = StringField('name', [validators.Length(min=4, max=25),validators.DataRequired()])
    description = StringField('Description', [validators.DataRequired()])

# home page
@csrf.exempt
@app.route('/')
def showHome():
    return redirect(url_for('showCatalog'))
# Create a new user
@app.route('/users/new/', methods=['GET', 'POST'])
def newUser():
    form = RegistrationForm(request.form)
    if request.method == 'POST' and form.validate():
        user_id = getUserID(request.form['email'])
        if not user_id:
            newUser = User(name=request.form['name'],email=request.form['email'],picture=request.form['picture'])
            session.add(newUser)
            session.commit()
            user = getUser(request.form['email'])
            login_session['username'] = user.name
            login_session['id'] = user.id
            login_session['email'] = user.email
            login_session['picture'] = user.picture
            return redirect(url_for('showUsers'))
        else:
            flash("Email already exist: %s" % request.form['email'])
            return render_template('register.html', form=form)
    else:
        return render_template('register.html', form=form)

# Show users
@csrf.exempt
@app.route('/users/')
def showUsers():
    if 'username' not in login_session:
        flash("Login before access this page" )
        return redirect('/login')
    #if not hasattr(login_session, 'id') :
    user = getUser(login_session['email'])
        # return "This page will show all my restaurants"
    flash("You are logged as %s" % login_session['username'])
    return render_template('user.html', user=user)

# Create anti-forgery state token
@csrf.exempt
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token


    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]


    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from the server token exchange we have to
        split the token first on commas and select the first index which gives us the key : value
        for the server access token then we split it on colons to pull out the actual token value
        and replace the remaining quotes with nothing so that it can be used directly in the graph
        api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    #login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output

    # DISCONNECT - Revoke a current user's token and reset their login_session


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session['access_token']
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: ' 
    print login_session['username']
    if access_token is None:
 	print 'Access Token is None'
    	response = make_response(json.dumps('Current user not connected.'), 401)
    	response.headers['Content-Type'] = 'application/json'
    	return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
	del login_session['access_token'] 
    	del login_session['gplus_id']
    	del login_session['username']
    	del login_session['email']
    	del login_session['picture']
    	response = make_response(json.dumps('Successfully disconnected.'), 200)
    	response.headers['Content-Type'] = 'application/json'
    	return response
    else:
	
    	response = make_response(json.dumps('Failed to revoke token for given user.', 400))
    	response.headers['Content-Type'] = 'application/json'
    	return response


# login check
@csrf.exempt
@app.route('/login_check/', methods=['POST'])
def loginCheck():
    if request.method == 'POST' and request.args.get('state') == login_session['state']:
        checkUser = getUser(request.form['email'])
        if not checkUser:
            flash("User with email %s not  exist " % request.form['email'])
            return redirect('/users/new')
        else:
           login_session['username'] = checkUser.name
           login_session['id'] = checkUser.id
           login_session['email'] = checkUser.email
           login_session['picture'] = checkUser.picture
           flash("Welcome %s " % login_session['username'])
           return redirect('/')
    else:
        return redirect('/users/new')
    # return "This page will be for making a new restaurant"
# Create anti-forgery state token
@csrf.exempt
@app.route('/logout')
def logout():
    if 'username' not in login_session:
        flash("Login before access this page" )
        return redirect('/login')

    del login_session['id']
    del login_session['username']
    del login_session['email']
    del login_session['picture']
    flash("You are successfully disconnected")
    return redirect('/')

# Catalogs
@csrf.exempt
@app.route('/catalog')
def showCatalog():
    catalogs=getCatalog()
    items = getCatalogItemRecents()
    return render_template('catalog.html', catalogs=catalogs,items=items)

# Create new Catalogs
@app.route('/catalog/new', methods=['GET', 'POST'])
def newCatalog():
    if 'username' not in login_session:
        flash("Login before access this page" )
        return redirect('/login')
    form = CatalogForm(request.form)
    if request.method == 'POST' and form.validate():
        catalog_id = getCatalogID(request.form['name'])
        if not catalog_id:
            newCatalog = Categories(name=request.form['name'],user_id=login_session['id'])
            session.add(newCatalog)
            session.commit()
            return redirect(url_for('showCatalog'))
        else:
            flash("Catalog already exist: %s" % request.form['name'])
            return render_template('new-catalog.html', form=form)
    else:
        return render_template('new-catalog.html', form=form)

# Edit Catalogs
@app.route('/catalog/<catalog_name>/edit', methods=['GET', 'POST'])
def editCatalog(catalog_name):
    if 'username' not in login_session:
        flash("Login before access this page" )
        return redirect('/login')
    form = CatalogForm(request.form)
    catalog = getCatalogByName(catalog_name)
    if request.method == 'POST' and form.validate():
        catalog_id = getCatalogID(request.form['name'])
        if not catalog_id:
            catalog.name = request.form['name']
        session.add(catalog)
        session.commit()
        flash('Catalog Successfully Edited')
        return redirect(url_for('showCatalog'))
    else:
        return render_template('catalogedit.html', catalog=catalog, form=form)

# Delete Catalogs
@app.route('/catalog/<catalog_name>/delete', methods=['GET', 'POST'])
def deleteCatalog(catalog_name):
    if 'username' not in login_session:
        flash("Login before access this page" )
        return redirect('/login')
    catalog = getCatalogByName(catalog_name)
    if request.method == 'POST':
        session.delete(catalog)
        session.commit()
        flash('Catalog Successfully deleted')
        return redirect(url_for('showCatalog'))
    else:
        return render_template('deletecatalog.html', catalog=catalog)

# Catalogs detail with its items
@app.route('/catalog/<catalog_name>/detail', methods=['GET', 'POST'])
def detailCatalog(catalog_name):
    catalog = getCatalogByName(name=catalog_name)
    items=getCatalogItemByCtlgId(catalog.id)
    return render_template('catalog-detail.html', catalog=catalog,items=items)

# Add items to catalog
@app.route('/catalog/<catalog_name>/add-items', methods=['GET', 'POST'])
def addItemsCatalog(catalog_name):
    if 'username' not in login_session:
        flash("Login before access this page" )
        return redirect('/login')
    catalog = getCatalogByName(catalog_name)
    form = ItemsForm(request.form)
    if request.method == 'POST' and form.validate():
        item_id = getItemsID(request.form['name'])
        if not item_id:
            newItem = CategoriesItem(name=request.form['name'],description=request.form['description'],categories_id=catalog.id,user_id=login_session['id'])
            session.add(newItem)
            session.commit()
            item=getItemByName(request.form['name'])
            return redirect(url_for('itemDetail',catalog_name=catalog,item=item))
        else:
            flash("Item already exist: %s" % request.form['name'])
            return render_template('AddItems.html', form=form)
    else:
        return render_template('AddItems.html', form=form)

# Catalogs detail with its items
@app.route('/catalog/<catalog_name>/<item>', methods=['GET', 'POST'])
def itemDetail(catalog_name,item):
    catalog = getCatalogByName(catalog_name)
    item=getItemByName(item)
    return render_template('item-detail.html', catalog=catalog,item=item)

# Edit items to catalog
@app.route('/catalog/<catalog_name>/<item>/edit', methods=['GET', 'POST'])
def editItemCatalog(catalog_name,item):
    if 'username' not in login_session:
        flash("Login before access this page" )
        return redirect('/login')
    catalog = getCatalogByName(catalog_name)
    editedItem=getItemByName(item)
    form = ItemsForm(request.form)
    if request.method == 'POST' and form.validate():
        item_id = getItemsID(request.form['name'])
        if not item_id:
            if request.form['name']:
                editedItem.name = request.form['name']
            if request.form['description']:
                editedItem.description = request.form['description']
            session.add(editedItem)
            session.commit()
            item=getItemByName(request.form['name'])
            return redirect(url_for('itemDetail',catalog_name=catalog,item=item))
        else:
            flash("Item already exist: %s" % request.form['name'])
            return render_template('editItem.html', item=editedItem,form=form)
    else:
        return render_template('editItem.html', item=editedItem, form=form)

# Delete item
@app.route('/catalog/<catalog_name>/<item>/delete', methods=['GET', 'POST'])
def deleteItem(catalog_name,item):
    if 'username' not in login_session:
        flash("Login before access this page" )
        return redirect('/login')
    item=getItemByName(item)
    if request.method == 'POST':
        session.delete(item)
        session.commit()
        flash('Item Successfully deleted')
        return redirect(url_for('showCatalog'))
    else:
        return render_template('deleteitem.html', item=item)

# JSON APIs to view cTALOG
@app.route('/catalog/JSON')
def catalogJSON():
    items = session.query(Categories).from_self(). \
        join(CategoriesItem.categories).from_self()
    return jsonify(Catalog=[i.serialize for i in items])

# User Helper Functions

def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None
def getUser(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user
    except:
        return None
def getCatalog():
    try:
        catalogs = session.query(Categories).all()
        return catalogs
    except:
        return None

def getCatalogID(name):
    try:
        catalog = session.query(Categories).filter_by(name=name).one()
        return catalog.id
    except:
        return None
def getCatalogByName(name):
    try:
        catalog = session.query(Categories).filter_by(name=name).one()
        return catalog
    except:
        return None
def getCatalogById(catalog_id):
    try:
        catalog = session.query(Categories).filter_by(id=catalog_id).one()
        return catalog
    except:
        return None
def getCatalogItem():
    try:
        items = session.query(CategoriesItem).all()
        return items
    except:
        return None
def getCatalogItemRecents():
    try:
        items = session.query(CategoriesItem).limit(10).all()
        return items
    except:
        return None
def getCatalogItemByCtlgId(item_id):
    try:
        items = session.query(CategoriesItem).filter_by(categories_id=item_id).all()
        return items
    except:
        return None
def getItemsID(name):
    try:
        item = session.query(CategoriesItem).filter_by(name=name).one()
        return item.id
    except:
        return None
def getItemByName(name):
    try:
        item = session.query(CategoriesItem).filter_by(name=name).one()
        return item
    except:
        return None

if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    #app.debug = True
    app.run(host='0.0.0.0', port=4300)
