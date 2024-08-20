import passport from "passport";
import local from "passport-local";
import usersModel from "../models/user.model.js";
import bcrypt from 'bcrypt'
import userModel from "../models/user.model.js";
import jwt from 'passport-jwt';

const LocalStrategy = local.Strategy;

const JWTStrategy = jwt.Strategy;
const ExtractJWT = jwt.ExtractJwt;

const cookieExtractor = (req) => {
    let token = null;
    if (req && req.cookies){
        token = req.cookies['token'];
    }
    return token;
}

const initializePassport = () => {

    

    passport.use('jwt', new JWTStrategy({
        jwtFromRequest: ExtractJWT.fromExtractors([cookieExtractor]),
        secretOrKey: 'ClaveSecretaJWT'
    }, async (jwt_payload, done) => {
        try {
            return done(null,jwt_payload)
        } catch (error) {
            return done(error);
        }
    }))

    passport.use('register', new LocalStrategy(
        {passReqToCallback:true,usernameField:"email"}, async (req, username, password, done) => {
            let userData = req.body;
            userData.role = 'user';
            try {
                let userExist = await usersModel.findOne({email: userData.email});
                if(userExist){
                    console.log('El email ya está registrado');
                    return done(null,false);
                }
                userData.password = bcrypt.hashSync(userData.password, bcrypt.genSaltSync(10));
                let newUser = new usersModel(userData);
                const userCreado = await newUser.save();
                return done(null, userCreado)
            } catch (error) {
                return done("Error al intentar registrar al usuario" + error);
            }
        }
    ));

    passport.use('login', new LocalStrategy({usernameField:"email"}, async(username,password,done) => {
        try {
            const user = await userModel.findOne({email:username});
            if(!user){
                console.log('Usuario inexistente');
                return done(null,false)
            }
            if(!bcrypt.compareSync(password, user.password)){
                console.log('Password incorrecto');
                return done(null,false)
            }
            // USUARIO LOGEADO
       
            
            return done(null,user)
        } catch (error) {
            return done("Error al intentar logear al usuario" + error);
        }
    }))



    passport.serializeUser((user,done)=> {
        done(null, user._id)
    })

    passport.deserializeUser(async (id, done) => {
        let user = await userModel.findById(id);
        done(null, user)
    });


}

export default initializePassport;