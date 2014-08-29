from bson import ObjectId
from flask import Flask, request, redirect, url_for, session, flash, g, \
     render_template
from flask_oauth import OAuth

from pymongo import Connection

import settings_local as settings

# configuration
DATABASE_URI = 'sqlite:////tmp/flask-oauth.db'
SECRET_KEY = 'development key'
DEBUG = True

# setup flask
app = Flask(__name__)
app.debug = DEBUG
app.secret_key = settings.APP_SECRET_KEY
oauth = OAuth()

# Use Twitter as example remote application
twitter = oauth.remote_app('twitter',
    # unless absolute urls are used to make requests, this will be added
    # before all URLs.  This is also true for request_token_url and others.
    base_url='https://api.twitter.com/1.1/',
    # where flask should look for new request tokens
    request_token_url='https://api.twitter.com/oauth/request_token',
    # where flask should exchange the token with the remote application
    access_token_url='https://api.twitter.com/oauth/access_token',
    # twitter knows two authorizatiom URLs.  /authorize and /authenticate.
    # they mostly work the same, but for sign on /authenticate is
    # expected because this will give the user a slightly different
    # user interface on the twitter side.
    authorize_url='https://api.twitter.com/oauth/authenticate',
    # the consumer keys from the twitter application registry.
    consumer_key=settings.TWITTER_CONSUMER_KEY,
    consumer_secret=settings.TWITTER_CONSUMER_SECRET
)

# setup sqlalchemy

database = Connection()['calabashdb']


@app.before_request
def before_request():
    g.user = None
    if 'user_id' in session:
        g.user = database.users.find_one({
            "_id": ObjectId(session['user_id'])
        })


@app.after_request
def after_request(response):
    return response


@twitter.tokengetter
def get_twitter_token():
    """This is used by the API to look for the auth token and secret
    it should use for API calls.  During the authorization handshake
    a temporary set of token and secret is used, but afterwards this
    function has to return the token and secret.  If you don't want
    to store this in the database, consider putting it into the
    session instead.
    """
    user = g.user
    if user is not None:
        return user['oauth_token'], user['oauth_secret']


@app.route('/')
def index():
    tweets = None
    if g.user is not None:

        fetch_next = True
        cursor = None

        users = []

        while fetch_next:
            response = twitter.get('friends/list.json', {
                "count": 200,
                "cursor": cursor or "",
                "access_token": get_twitter_token()
            })

            users += response.data['users']
            cursor = response.data['next_cursor']
            fetch_next = bool(cursor)

        import pdb; pdb.set_trace()

    return render_template('index.html', tweets=tweets, users=[])


@app.route('/tweet', methods=['POST'])
def tweet():
    """Calls the remote twitter API to create a new status update."""
    if g.user is None:
        return redirect(url_for('login', next=request.url))
    status = request.form['tweet']
    if not status:
        return redirect(url_for('index'))
    resp = twitter.post('statuses/update.json', data={
        'status':       status
    })
    if resp.status == 403:
        flash('Your tweet was too long.')
    elif resp.status == 401:
        flash('Authorization error with Twitter.')
    else:
        flash('Successfully tweeted your tweet (ID: #%s)' % resp.data['id'])
    return redirect(url_for('index'))


@app.route('/login')
def login():
    """Calling into authorize will cause the OpenID auth machinery to kick
    in.  When all worked out as expected, the remote application will
    redirect back to the callback URL provided.
    """
    return twitter.authorize(callback=url_for('oauth_authorized',
        next=request.args.get('next') or request.referrer or None))


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You were signed out')
    return redirect(request.referrer or url_for('index'))


@twitter.tokengetter
def get_twitter_token(token=None):
    return session.get('twitter_token')


@app.route('/oauth-authorized')
@twitter.authorized_handler
def oauth_authorized(resp):
    """Called after authorization.  After this function finished handling,
    the OAuth information is removed from the session again.  When this
    happened, the tokengetter from above is used to retrieve the oauth
    token and secret.

    Because the remote application could have re-authorized the application
    it is necessary to update the values in the database.

    If the application redirected back after denying, the response passed
    to the function will be `None`.  Otherwise a dictionary with the values
    the application submitted.  Note that Twitter itself does not really
    redirect back unless the user clicks on the application name.
    """
    next_url = request.args.get('next') or url_for('index')
    if resp is None:
        flash(u'You denied the request to sign in.')
        return redirect(next_url)

    user = database.users.find_one({
        "username": resp['screen_name']
    })

    # user never signed on
    if user is None:
        user_id = database.users.insert({
            "username": resp['screen_name']
        })

        user = database.users.find_one({
            "_id": user_id
        })

    # in any case we update the authenciation token in the db
    # In case the user temporarily revoked access we will have
    # new tokens here.
    database.users.update({
        "_id": user['_id']
    }, {
        "$set": {
            "oauth_token": resp['oauth_token'],
            "oauth_secret": resp['oauth_token_secret']
        }
    })

    session['user_id'] = str(user['_id'])

    flash('You were signed in')
    return redirect(next_url)


if __name__ == '__main__':
    app.run()
