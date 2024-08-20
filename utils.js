import {fileURLToPath} from 'url';
import {dirname} from 'path';
import passport from 'passport';

const __filename = fileURLToPath(import.meta.url)
export const __dirname = dirname(__filename);

export const passportCall = (strategy) => {
    return async (req,res,next) => {
        passport.authenticate(strategy, function (err,user,info){
            if(err) return next(err);
            if(!user){
                return res.status(401).send({error:info.messages?info.message:info.toString()})

            }
            req.user = user;
            next();
        })(req,res,next)
    }
}

