import logging
import os
import re
import requests
import json
import secrets
import sys
# import rollbar
from uuid import uuid4

from flask import Flask, abort, jsonify, redirect, request
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy

try:
    from dotenv import load_dotenv
    dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
    load_dotenv(dotenv_path)
except:
    pass

app = Flask(__name__)
cors_allowed_origin = os.environ['CORS_ALLOWED_ORIGINS']
cors = CORS(app, origins=('*' if not cors_allowed_origin else cors_allowed_origin.split(',')))
# cors = CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# rollbar_api_key = os.environ['ROLLBAR_API_KEY']

# rollbar.init(rollbar_api_key)
# rollbar.report_message('Rollbar is configured correctly')

if 'DYNO' in os.environ:
    app.logger.addHandler(logging.StreamHandler(sys.stdout))
    app.logger.setLevel(logging.ERROR)

mailgun_domain = os.environ['MAILGUN_DOMAIN']
mailgun_key = os.environ['MAILGUN_API_KEY']
mailgun_send_url = 'https://api.mailgun.net/v3/%s/messages' % mailgun_domain

registration_enabled = os.environ.get('REGISTRATION_ENABLED') in ['yes', 'true']
registration_password = os.environ['REGISTRATION_PASSWORD'] if registration_enabled else None
default_sender = os.environ.get('DEFAULT_SENDER') or ('fwdform@%s' % mailgun_domain)

hapikey = os.environ.get('HUBSPOT_API_KEY')

slack_auth_key = os.environ.get('SLACK_AUTH_KEY')
slack_contact_channel_id = os.environ.get('SLACK_CONTACT_CHANNEL_ID')
slack_newsletter_channel_id = os.environ.get('SLACK_NEWSLETTER_CHANNEL_ID')
slack_bot_name = os.environ.get('SLACK_BOT_NAME')

recaptcha_secret_key = os.environ.get('RECAPTCHA_SECRET_KEY')

contact_form_id = os.environ.get('CONTACT_FORM_ID')
newsletter_form_id = os.environ.get('NEWSLETTER_FORM_ID')

ESCAPE_SEQUENCE_RE = re.compile(r"\\|%")
UNESCAPE_SEQUENCE_RE = re.compile(r"\\(\\|%)")
PARAM_RE = re.compile(r"(?<!\\)%((?:[^%]|\\%)*?(?:[^%\\]|\\%))%")

def escape(text):
    return re.sub(ESCAPE_SEQUENCE_RE, lambda m: '\\' + m.group(0), text)


def unescape(text):
    return re.sub(UNESCAPE_SEQUENCE_RE, lambda m: m.group(1), text)


def substitute_params(template, params):
    if not template:
        return None
    return unescape(re.sub(PARAM_RE, lambda m: escape(params[unescape(m.group(1))]), template))


def send_mail(to_address, from_address, subject, body, html_body=None, reply_to_address=None):
    message = {
        'to': [to_address],
        'from': from_address,
        'subject': subject,
        'text': body
    }
    if html_body:
        message['html'] = html_body
    if reply_to_address:
        message['h:Reply-To'] = reply_to_address

    result = requests.post(
        mailgun_send_url,
        auth=('api', mailgun_key),
        data=message
    )
    if result.status_code != requests.codes.ok:
        app.logger.error('Received %(status)d error while sending email to %(email)s: %(error)s', {'status': result.status_code, 'email': to_address, 'error': result.text})
        abort(500)


def falsey_to_none(value):
    return value if value else None


def request_wants_json():
    best = request.accept_mimetypes.best_match(['application/json', 'text/plain'])
    return best == 'application/json' and request.accept_mimetypes[best] > request.accept_mimetypes['text/plain']


class User(db.Model):

    def __init__(self, email):
        self.email = falsey_to_none(email)
        self.public_token = str(uuid4())
        self.private_token = secrets.token_urlsafe(16)

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(320), unique=True, nullable=False) # https://tools.ietf.org/html/rfc5321#page-63
    public_token = db.Column(db.String(36), unique=True, nullable=False)
    private_token = db.Column(db.String(32), nullable=False)


class Form(db.Model):

    def __init__(self, user_id, subject, body, html_body, response_subject, response_body, response_html_body, response_from, response_reply_to):
        self.user_id = user_id
        self.public_token = str(uuid4())
        self.subject = falsey_to_none(subject)
        self.body = falsey_to_none(body)
        self.html_body = falsey_to_none(html_body)
        self.response_subject = falsey_to_none(response_subject)
        self.response_body = falsey_to_none(response_body)
        self.response_html_body = falsey_to_none(response_html_body)
        self.response_from = falsey_to_none(response_from)
        self.response_reply_to = falsey_to_none(response_reply_to)

    id = db.Column(db.Integer, primary_key=True)
    public_token = db.Column(db.String(36), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    subject = db.Column(db.Text(), nullable=False)
    body = db.Column(db.Text(), nullable=False)
    html_body = db.Column(db.Text(), nullable=True)
    response_subject = db.Column(db.Text(), nullable=True)
    response_body = db.Column(db.Text(), nullable=True)
    response_html_body = db.Column(db.Text(), nullable=True)
    response_from = db.Column(db.String(320), nullable=True)
    response_reply_to = db.Column(db.String(320), nullable=True)


@app.route('/')
def index():
    return redirect('https://github.com/glassechidna/fwdform2')

@app.route('/register', methods=['POST'])
def register():
    if not registration_enabled:
        abort(500)
    if registration_password and request.form['password'] != registration_password:
        abort(403)

    user = User.query.filter_by(email=request.form['email']).first()
    if user:
        return ('Email already registered', 403)

    user = User(request.form['email'])
    db.session.add(user)
    db.session.commit()

    if request_wants_json():
        return jsonify(
            public_token=user.public_token,
            private_token=user.private_token
        )
    else:
        return f"Public token: {user.public_token}, Private token: {user.private_token}"

@app.route('/user/<public_token>', methods=['DELETE'])
def deregister(public_token):
    user = User.query.filter_by(public_token=public_token).first()
    if not user:
        return ('User not found', 404)

    token = request.form['token']
    if user.private_token != token:
        return ('Token invalid', 403)

    email = user.email
    Form.query.filter_by(user_id=user.id).delete()
    db.session.delete(user)
    db.session.commit()

    if request_wants_json():
        return jsonify()
    else:
        return f"Registration for {email} deleted"

@app.route('/user/<public_token>', methods=['POST'])
def forward_message(public_token):
    user = User.query.filter_by(public_token=public_token).first()
    if not user:
        return ('User not found', 404)

    subject = request.form.get('name') or request.form.get('email') or 'Anonymous'
    send_mail(
        to_address=user.email,
        from_address=default_sender,
        subject=f"Message from {subject}",
        body=request.form['message'],
        reply_to_address=request.form.get('email'),
    )

    if 'redirect' in request.form:
        return redirect(request.form['redirect'])

    return jsonify() if request_wants_json() else 'Message submitted'

@app.route('/user/<public_token>/form', methods=['POST'])
def register_form(public_token):
    user = User.query.filter_by(public_token=public_token).first()
    if not user:
        return ('User not found', 404)

    token = request.form['token']
    if user.private_token != token:
        return ('Token invalid', 403)

    form = Form(
        user_id=user.id,
        subject=request.form['subject'],
        body=request.form['body'],
        html_body=request.form.get('html_body'),
        response_subject=request.form.get('response_subject'),
        response_body=request.form.get('response_body'),
        response_html_body=request.form.get('response_html_body'),
        response_from=request.form.get('response_from'),
        response_reply_to=request.form.get('response_reply_to')
    )
    db.session.add(form)
    db.session.commit()

    if request_wants_json():
        return jsonify(
            form_token=form.public_token
        )
    else:
        return f"Form token: {form.public_token}"

@app.route('/form/<form_token>', methods=['DELETE'])
def deregister_form(form_token):
    form = Form.query.filter_by(public_token=form_token).first()
    if not form:
        return ('Form not found', 404)

    user = User.query.filter_by(id=form.user_id).first()
    if not user:
        return ('User not found', 404)

    token = request.form['token']
    if user.private_token != token:
        return ('Token invalid', 403)

    subject = form.subject
    db.session.delete(form)
    db.session.commit()

    return jsonify() if request_wants_json() else f"Form '{subject}' deleted"

@app.route('/form/<form_token>', methods=['POST'])
def forward_form(form_token):
    # try:
    #     b = a + 1
    # except:
    #     rollbar.report_exc_info()
    form = Form.query.filter_by(public_token=form_token).first()
    if not form:
        return ('form-not-found', 404)

    user = User.query.filter_by(id=form.user_id).first()
    if not user:
        return ('user-not-found', 404)

    submitter_email = request.form.get('email')
    honeypot = request.form.get('_gotcha')

    g_recaptcha_response = request.form.get('g-recaptcha-response')

    if g_recaptcha_response:
        recaptcha_endpoint = 'https://www.google.com/recaptcha/api/siteverify?secret=' + recaptcha_secret_key + '&response=' + g_recaptcha_response
        headers = {}
        headers["Content-Type"]="application/x-www-form-urlencoded"
        headers["Content-Length"]=548
        data = json.dumps({})
        r = requests.post( url = recaptcha_endpoint, data = data, headers = headers )

        print('================== RECAPTCHA RESPONSE START ===================')
        print(g_recaptcha_response)
        print('================== RECAPTCHA RESPONSE END =====================')


    if not g_recaptcha_response or r.json()["success"] == False:
        return ('captcha-invalid', 404)

    if honeypot:
        return ('error', 404)

    if not submitter_email:
        return ('email-blank', 404)

    if r.json()["success"] == True and not honeypot and submitter_email:
        if form_token == contact_form_id:
            send_mail(
                to_address=user.email,
                from_address=default_sender,
                subject=substitute_params(form.subject, request.form),
                body=substitute_params(form.body, request.form),
                reply_to_address=submitter_email,
            )

            submitter_name = request.form.get('name')
            submitter_name_list = submitter_name.split()
            submitter_first_name = submitter_name_list[0]
            submitter_name_list.pop(0)
            submitter_last_name = " ".join(submitter_name_list)

            submitter_phone = request.form.get('phone')
            submitter_subject = request.form.get('subject')
            submitter_body = request.form.get('body')

            # 'https://api.hubapi.com/contacts/v1/contact/createOrUpdate/email/' + submitter_email + '?hapikey=' + hapikey
            # hubspot_endpoint = 'https://api.hubapi.com/contacts/v1/contact/?hapikey=' + hapikey
            hubspot_endpoint = 'https://api.hubapi.com/contacts/v1/contact/createOrUpdate/email/' + submitter_email + '?hapikey=' + hapikey
            headers = {}
            headers["Content-Type"]="application/json"
            data = json.dumps({
              "properties": [
                {
                  "property": "email",
                  "value": submitter_email
                },
                {
                  "property": "firstname",
                  "value": submitter_first_name
                },
                {
                  "property": "lastname",
                  "value": submitter_first_name
                },
                {
                  "property": "phone",
                  "value": submitter_phone
                },
                {
                  "property": "subject",
                  "value": submitter_subject
                },
                {
                  "property": "message",
                  "value": submitter_body
                }
              ]
            })


            r = requests.post( url = hubspot_endpoint, data = data, headers = headers )

            print('================== HUBSPOT RESPONSE START ===================')
            print(r.text)
            print('================== HUBSPOT RESPONSE END =====================')

            slack_endpoint = 'https://slack.com/api/chat.postMessage'
            headers = {}
            headers["Content-Type"]="application/json"
            headers["Authorization"]=slack_auth_key
            data = json.dumps({
              "channel": slack_contact_channel_id,
              "text": "*" + submitter_name + "* has submitted the contact form.\n\n*Email:* " + submitter_email + "\n*Phone:* " + submitter_phone + "\n*Subject:* " + submitter_subject + "\n*Message:*\n" + submitter_body + "\n___________________________________________\n",
              "username": slack_bot_name})

            r = requests.post( url = slack_endpoint, data = data, headers = headers )

            print('================== SLACK RESPONSE START ===================')
            print(r.text)
            print('================== SLACK RESPONSE END =====================')
        elif form_token == newsletter_form_id:
            hubspot_endpoint = 'https://api.hubapi.com/contacts/v1/contact/createOrUpdate/email/' + submitter_email + '?hapikey=' + hapikey
            headers = {}
            headers["Content-Type"]="application/json"
            data = json.dumps({
              "properties": [
                {
                  "property": "email",
                  "value": submitter_email
                },
                {
                  "property": "newsletter",
                  "value": "Yes"
                }
              ]
            })

            r = requests.post( url = hubspot_endpoint, data = data, headers = headers )

            print('================== HUBSPOT RESPONSE START ===================')
            print(r.text)
            print('================== HUBSPOT RESPONSE END =====================')

            slack_endpoint = 'https://slack.com/api/chat.postMessage'
            headers = {}
            headers["Content-Type"]="application/json"
            headers["Authorization"]=slack_auth_key
            data = json.dumps({
              "channel": slack_newsletter_channel_id,
              "text": "*" + submitter_email+ "* has subscribed for the newsletter.",
              "username": slack_bot_name})

            r = requests.post( url = slack_endpoint, data = data, headers = headers )

            print('================== SLACK RESPONSE START ===================')
            print(r.text)
            print('================== SLACK RESPONSE END =====================')
        response_message = 'form-submitted'
    else:
        response_message = 'form-not-submitted'

        # if submitter_email and form.response_body:
        #     send_mail(
        #         to_address=submitter_email,
        #         from_address=form.response_from or default_sender,
        #         subject=substitute_params(form.response_subject, request.form) or 'Your confirmation',
        #         body=substitute_params(form.response_body, request.form),
        #         html_body=substitute_params(form.response_html_body, request.form),
        #         reply_to_address=form.response_reply_to
        #     )

    if 'redirect' in request.form:
        return redirect(request.form['redirect'])

    return jsonify() if request_wants_json() else response_message
