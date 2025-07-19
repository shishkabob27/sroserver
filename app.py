from flask import Flask, make_response, request, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from flask_bcrypt import Bcrypt
import uuid
import re
app = Flask(__name__)
bcrypt = Bcrypt(app)

class Base(DeclarativeBase):
	pass

db = SQLAlchemy(model_class=Base)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///shadowrun.db"
db.init_app(app)

class Account(db.Model):
	__tablename__ = "accounts"
	email = db.Column(db.String(255), primary_key=True)
	password = db.Column(db.String(255), nullable=False)
	identity_hash = db.Column(db.String(36), nullable=False, unique=True) #identity hash for account
	session_hash = db.Column(db.String(36), unique=True) #hash for current session, resets on login
	username = db.Column(db.String(14)) #LauncherDisplayName, client only allows 14 characters
	verify_code = db.Column(db.String(6)) #verification code for email on registration
 
class ResultCode:
	OK = 0
	IDENTITY_NOT_FOUND = 1
	INVALID_DISPLAY_NAME = 2
	INVALID_GAME_NAME = 3
	PLAYER_IS_BANNED = 4
	INVALID_SEARCH_STRING = 5
	HAS_FORBIDDEN_WORDS = 6

@app.route('/SRO/configs/SRO_23.3/SteamWindows/LauncherConfig.xml')
def LauncherConfig():
	return send_file('static/LauncherConfig.xml')

def IsEmailValid(email) -> bool:
    
	#Size of email
	if len(email) > 255:
		return False

	pattern = re.compile(r"[-A-Za-z0-9!#$%&'*+/=?^_`{|}~]+(?:\.[-A-Za-z0-9!#$%&'*+/=?^_`{|}~]+)*@(?:[A-Za-z0-9](?:[-A-Za-z0-9]*[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[-A-Za-z0-9]*[A-Za-z0-9])?", re.IGNORECASE)
	if pattern.match(email):
		return True

	return False

def IsUsernameValid(username) -> bool:
	if len(username) > 16:
		return False

	#TODO: Bad words filter

	return True

def SendEmailVerification(email, verify_code):
	pass

@app.route('/AccountSystem/Accounts/Cliffhanger/Register', methods=['POST'])
def RegisterWithCliffhanger():
	#get json data
	data = request.get_json()
 
	input_email = data["Email"]
	input_password = data["Password"]
 
	#check if email is valid
	if not IsEmailValid(input_email):
		return jsonify({
			"Code": ResultCode.IDENTITY_NOT_FOUND,
			"Success": False,
			"Message": "not a valid e-mail address",
		})
 
	#check if email is unique
	if Account.query.filter_by(email=input_email).first() is None:
		
  		#add account to database
		account = Account(
			email=input_email,
			password=bcrypt.generate_password_hash(input_password).decode('utf-8'),
			identity_hash=str(uuid.uuid4()),
			verify_code=str(uuid.uuid4())[:6] #6 digit code
		)
		db.session.add(account)
		db.session.commit()
  
		#send email
		SendEmailVerification(input_email, account.verify_code)
		
		return jsonify({
			"Code": ResultCode.OK,
			"Success": True,
			"IdentityHash": account.identity_hash,
		})
  
	#email is not unique
	return jsonify({
		"Code": ResultCode.IDENTITY_NOT_FOUND,
		"Success": False,
		"Message": "NotUnique",
	}), 400
 
 
@app.route('/AccountSystem/Accounts/Cliffhanger/Verify', methods=['POST'])
def VerifyWithCliffhanger():
	#get json data
	data = request.get_json()
 
	input_email = data["Email"]
	input_verify_code = data["VerificationCode"].strip().lower()
 
	#check if email is valid
	if not IsEmailValid(input_email):
		return jsonify({
			"Code": ResultCode.IDENTITY_NOT_FOUND,
			"Success": False,
			"Message": "not a valid e-mail address",
		}), 400
  
	#check if verify code is valid
	if len(input_verify_code) != 6:
		return jsonify({
			"Code": -1,
			"Success": False,
			"Message": "CodeInvalid",
		}), 400
 
	#check if email exists
	account = Account.query.filter_by(email=input_email).first()
	if account is None:
		return jsonify({
			"Code": ResultCode.IDENTITY_NOT_FOUND,
			"Success": False,
			"Message": "Account Not Found",
		}), 400
  
	#check if verify code is correct
	if account.verify_code == input_verify_code:
		account.verify_code = None
		db.session.commit()
		
		return jsonify({
			"Code": ResultCode.OK,
			"Success": True,
		})
  
	#verify code is incorrect
	return jsonify({
		"Code": -1,
		"Success": False,
		"Message": "CodeInvalid",
	}), 400

@app.route('/AccountSystem/Accounts/Cliffhanger/ResendVerificationCode', methods=['POST'])
def ResendVerificationCode():
	#get json data
	data = request.get_json()
 
	input_email = data["Email"]
 
	#check if email is valid
	if not IsEmailValid(input_email):
		return jsonify({
			"Code": ResultCode.IDENTITY_NOT_FOUND,
			"Success": False,
			"Message": "not a valid e-mail address",
		})
  
	#check if email exists
	account = Account.query.filter_by(email=input_email).first()
	if account is None:
		return jsonify({
			"Code": ResultCode.IDENTITY_NOT_FOUND,
			"Success": False,
			"Message": "Account Not Found",
		}), 400
  
	#generate new verify code
	account.verify_code = str(uuid.uuid4())[:6]
	db.session.commit()
 
	#send email
	SendEmailVerification(input_email, account.verify_code)
  
	return jsonify({
		"Code": ResultCode.OK,
		"Success": True,
	})
 
@app.route('/AccountSystem/Accounts/Cliffhanger/Authenticate', methods=['POST'])
def AuthenticateWithCliffhanger():
	#get json data
	data = request.get_json()
 
	user_email_input = data["Email"]
	user_password_input = data["Password"]
 
	#check if email is valid
	if not IsEmailValid(user_email_input):
		return jsonify({
			"Code": ResultCode.IDENTITY_NOT_FOUND,
			"Success": False,
			"IsVerified": False,
			"Message": "The Email field is not a valid e-mail address",
		}), 400
 
	#check if email exists
	account = Account.query.filter_by(email=user_email_input).first()
	if account is not None:
		#check if password is correct
		if bcrypt.check_password_hash(account.password, user_password_input):
      
			#Create new session hash upon successful login
			account.session_hash = str(uuid.uuid4())
			db.session.commit()

			return jsonify({
				"Code": ResultCode.OK,
				"IdentityHash": account.identity_hash,
				"SessionHash": account.session_hash,
				"IsVerified": account.verify_code is None,
				"GameKeyReplacementText": "Dummy", # this allows the client to not prompt of a game key
			})
		else: #password is incorrect
			return jsonify({
				"Code": -1,
				"Success": False,
				"IsVerified": False,
				"Message": "WrongPassword",
			}), 400
	
	#email does not exist
	return jsonify({
		"Code": -2,
		"Success": False,
		"Message": "AccountNotFound",
	}), 400
 
@app.route('/AccountSystem/Accounts/GetAccountForHash', methods=['POST'])
def GetAccountForHash():
	#get json data
	data = request.get_json()
 
	input_session_hash = data["SessionHash"]
 
	#check if session hash exists
	account = Account.query.filter_by(session_hash=input_session_hash).first()
	if account is not None:
		return jsonify({
			"Code": ResultCode.OK,
			"IdentityHash": account.identity_hash,
		})
	
	#session hash does not exist
	return jsonify({
		"Code": ResultCode.IDENTITY_NOT_FOUND,
		"Message": "AccountNotFound",
	})

@app.route('/AccountSystem/Accounts/PlayerActivity/GetPlayerInfo', methods=['POST'])
def GetPlayerInfo():
	#get json data
	data = request.get_json()
 
	input_identity_hashes = data["IdentityHashes"]
 
	player_info_results = []
 
	for identity_hash in input_identity_hashes:
		account = Account.query.filter_by(identity_hash=identity_hash).first()
		if account is not None:
			player_info_results.append({
				"IdentityHash": account.identity_hash,
				"PlayerInfo": [
					{
						"Key": "LauncherDisplayName",
						"Value": account.username #if this is null, the client will prompt the user to set a display name
					}
				]
			})
		
	return jsonify({
		"PlayerInfoResults": player_info_results
	})
 
@app.route('/AccountSystem/Accounts/PlayerActivity/SetPlayerInfo', methods=['POST'])
def SetPlayerInfo():
	#get json data
	data = request.get_json()
 
	input_session_hash = data["SessionHash"]
	input_player_info = data["PlayerInfo"]

	#check if session hash exists
	account = Account.query.filter_by(session_hash=input_session_hash).first()
	if account is not None:
		#check if "LauncherDisplayName" is in player info
		launcher_display_name = None
		if "LauncherDisplayName" in input_player_info:
			launcher_display_name = input_player_info["LauncherDisplayName"]
   
			is_valid = IsUsernameValid(launcher_display_name)
			if not is_valid:
				return jsonify({
					"Code": ResultCode.INVALID_DISPLAY_NAME,
					"Message": "InvalidDisplayName"
				})
    
			account.username = launcher_display_name
			db.session.commit()
   
			return jsonify({
				"Code": ResultCode.OK
			})
		
	return jsonify({
		"Code": ResultCode.INVALID_DISPLAY_NAME,
		"Message": "InvalidDisplayName"
	})
 

@app.route('/CouponSystem/Api/v1/Accounts/<uuid:UserID>/History', methods=['GET'])
def GetCouponHistory(UserID):
	return jsonify([
		{
			"CouponCode": "000000",
			"PackageTechnicalName": "SRO-GAME-KEY",
			"PackageName": "Shadowrun Chronicles",
		}
	])

@app.route('/CouponSystem/Api/v1/Coupon/Redeem/', methods=['GET'])
def RedeemCoupon():
	#coupon_code = request.args.get('Code')
	#account_id = request.args.get('AccountId')
	#app_id = request.args.get('AppId')
	
	return jsonify({
		"code": 6,
		#"PackageTechnicalName": "SRO-GAME-KEY",
	})
 
@app.route('/CouponSystem/Api/v1/Coupon/Return', methods=['GET'])
def ReturnCoupon():
	return jsonify({
		"code": 3
	})
 
@app.route('/AccountSystem/Accounts/Sessions/Heartbeat', methods=['POST'])
def Heartbeat():
	return jsonify({
		"Code": ResultCode.OK
	})
 
@app.route('/SRO/configs/SRO_23.3/SteamWindows/config.xml')
def BaseConfig():
	return send_file('static/config.xml')

@app.route('/servers<timestamp>.txt')
def Servers(timestamp):
	return "fra-sro-gam01.cliffhanger-productions.com:80"

if __name__ == '__main__':
    
	#write secret key to file if it doesn't exist
	secret_key_file = "secret_key.txt"
	try:
		with open(secret_key_file, "r") as f:
			app.secret_key = f.read()
	except FileNotFoundError:
		with open(secret_key_file, "w") as f:
			app.secret_key = str(uuid.uuid4())
			f.write(app.secret_key)
		
	with app.app_context():
		db.create_all()
		db.session.commit()
  
	app.run(debug=True, port=7000)