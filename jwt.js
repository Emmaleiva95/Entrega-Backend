
import  jwt  from 'jsonwebtoken';

const PRIVATE_KEY = "ClaveSecretaJWT";

export const generateToken = (user) => {
    const token = jwt.sign({user}, PRIVATE_KEY, {expiresIn:'24h'})
    return token;
}


export const authToken = (req, res, next) => {
    // ACCEDEMOS A LA COOKIE DE LA PETICION
    const token = req.cookies.token;

    if(!token) return res.status(401).json({ message: "No se encontro token, autorización denegada."})

    //verificamos el token
    jwt.verify(
        token,
        TOKEN_SECRET,
        (err, data) => {
            if(err) return res.status(403).send({ message: "El token no es valido!"})
            // PASAMOS A TRAVÉS DE LA REQ, LA INFO DEL TOKEN (id, nombre) A LA RUTA FINAL (perfil)
            req.usuario = data;
            next();
        }
    )
}