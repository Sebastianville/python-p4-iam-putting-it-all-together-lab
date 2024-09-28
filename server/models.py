from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin

from config import db, bcrypt

#encrypt the password so they aren't in plaintext and you will do this by hashing it

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'
   
   
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    image_url = db.Column(db.String)
    bio = db.Column(db.String)
    #private attribute will be managed via proerties
    _password_hash = db.Column(db.String)
    
    recipes = db.relationship('Recipe', back_populates="user")

    serialize_rules = ('recipes.user', '-_password_hash', )

    def __repr__(self):
        return f'<User {self.id}, {self.username}>'

    #This will allow us to set password_hash directly inside the sqlite database. 
    @hybrid_property
    def password_hash(self):
        raise AttributeError("Password hashes may not be viewed.")
    
    @password_hash.setter 
    def password_hash(self,password):
        #generate_passwoord_hash is a boiler plate(a built in) method that is given to us by bycrpt that encrypts plaintext 
        password_hash = bcrypt.generate_password_hash(password.encode("utf-8"))
        #the decode will make the password shorter in the database 
        self._password_hash = password_hash.decode('utf-8')
    
    def authenticate(self, password):
        #using a built in bcrypt method. This returns True or False
        return bcrypt.check_password_hash(self._password_hash, password.encode('utf-8'))


class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'
    #__table_args__ = (db.CheckConstraint("length(instructions) >= 50"),)
    
    id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer)
    user_id = db.Column(db.Integer(), db.ForeignKey("users.id"))


    user = db.relationship('User', back_populates='recipes')

    serialize_rules = ('-user.recipes', )

    @validates('title')
    def validate_title(self, key, title):
        if not title:
            raise ValueError('Title is required')
        return title

    @validates('instructions')
    def validate_instructions(self, key, instructions):
        if len(instructions) < 50:
            raise ValueError('Instructions must be at least 50 characters long')
        return instructions

    def __repr__(self):
        return f'<Recipe {self.id}, {self.title}'