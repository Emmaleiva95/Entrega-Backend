import { Router } from "express";
import usersModel from "../models/user.model.js";

import bcrypt from 'bcrypt'
import passport from "passport";
import { generateToken } from "../../jwt.js";
import { passportCall } from "../../utils.js";


const router = Router();


router.get("/api/users", async(req,res) => {
    const users = await usersModel.find();
    res.send(users);
})

/* REGISTRO */
router.post("/api/users/register", passport.authenticate('register',{failureRedirect:'/api/users/failregister'}) , async (req,res) => {
    res.send({status:'success',message:'Usuario registrado exitosamente'});
} )

router.post('/api/users/failregister', async (req,res) => {
    res.send({error:"failed register"});
})

/* LOGIN */
router.post("/api/users/login", passport.authenticate('login',{failureRedirect:'/api/users/faillogin'}) , async (req,res) => {
    console.log(req.user)
    const userData = { first_name: req.user.first_name,
        last_name: req.user.last_name,
        age: req.user.age,
        email: req.user.email}
    req.session.user = userData;
    //CREO EL TOKEN DE ACCESO
    const token = generateToken(userData);
    // GUARDO EL TOKEN EN UNA COOKIE
    res.cookie('token', token, {maxAge:60*60*1000,httpOnly:true})

    res.send({status:'success',payload:req.user});
} )

router.post('/api/users/faillogin', async (req,res) => {
    res.send({error:"failed login"});
})

// PERFIL O CURRENT

router.get('/api/users/current', passportCall('jwt'), async (req,res) => {
    console.log('datos del usuario')
    res.send(req.user);
})


export default router;