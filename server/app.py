#!/usr/bin/env python3

from flask import request, session, make_response, jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe


class Signup(Resource):
    def post(self):
        data = request.get_json()
        new_user = User(bio=data.get('bio'), image_url=data.get('image_url'),
        #password_hash= data.get('password') will enable the @password_hash.setter thus running the encryption that was written in models.py
        username= data.get('username'))
        new_user.password_hash=data.get('password')
        try: 
         db.session.add(new_user)
         db.session.commit()
         session["user_id"] = new_user.id
         return make_response(new_user.to_dict(), 201)
        
        except IntegrityError:
            return {"error": "422 Unprocessable Entity"}, 422


#Checksession is checking who is currently login and returning that inforomation to the client. This is adventagous because Flak session will automatically store information on the client side. Flask session also stores who is logged in the backend hence the Checksession 
class CheckSession(Resource):
      def get(self):
        user_id = session['user_id']
        if user_id:
            cur_user = User.query.filter_by(id=user_id).first()
            return make_response(cur_user.to_dict(), 200)
        return make_response({}, 401)

class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")
        user = User.query.filter(User.username == username).first()
        #Check if the password is correct
        if user:
            #the authenticate is coming from models.py 
            if user.authenticate(password):
                #if the password is correct then set sesssion on user.id and equaling it to user.id. This is HOW we can PERSIST who is currently LOGGED IN 
                session["user_id"] = user.id
                return make_response(user.to_dict(), 200)
        #401 means unauthorized
        return make_response({"error": "401 Unauthorized"}, 401)

class Logout(Resource):
     def delete(self):
        if session["user_id"]: 
            session["user_id"] = None
            return make_response({}, 204)
        else: 
            return make_response({'error message': 'Unauthorized'}, 401)


class RecipeIndex(Resource):
    def get(self):
        if session.get('user_id'):
            recipes = [recipe.to_dict() for recipe in Recipe.query.all()]
            return recipes, 200
        return {'error': '401 Unauthorized'}, 401

    def post(self):
        if session.get('user_id'):
            try:
                data = request.get_json()
                new_recipe = Recipe(
                    title=data['title'],
                    instructions=data['instructions'],
                    minutes_to_complete=data['minutes_to_complete'],
                    user_id=session['user_id']
                )
                db.session.add(new_recipe)
                db.session.commit()
                return new_recipe.to_dict(), 201
            except (ValueError, IntegrityError):
                return {'error': '422 Unprocessable Entity'}, 422
        return {'error': '401 Unauthorized'}, 401
   



api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)