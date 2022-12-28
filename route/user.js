import express from "express";
import { userModel } from "../Database/user.js";
import bodyParser from "body-parser";
const route = express.Router();
import  swaggerUi from 'swagger-ui-express';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
dotenv.config();
import {signUpMiddleware,signInMiddleware,updatePasswordMiddleware} from  '../middlewares/user.js';


route.post('/user/register', bodyParser.json(), signUpMiddleware(userModel), async(req,res) =>{
    const { name, email, password } = req.body.userinfo;
    try {
        let user = new userModel({ name, email, password });
        console.log(user);
        await user.save();
        return res.status(201).send({
            message: "User created"
        });
    }
    catch (error) {
        console.log(error);
    }
});


route.post('/user/signin', bodyParser.json(), signInMiddleware(userModel,process.env.SIGN),(req, res) => {
    const {token} = req.body
    return res.status(201).send({
        message: "Signed in Successfully",
        token: token,
    })

});


route.put('/user/update', bodyParser.json(),updatePasswordMiddleware(userModel,process.env.SIGN),  async(req, res) => {
   try {   
            let isUser = jwt.verify(req.headers.token, process.env.SIGN)
            let { password } = req.body.userinfo;
            password =  bcrypt.hash(password, 12);
            let user =  userModel.updateOne({ email: isUser.email }, { $set: { password: password } });
            console.log(user);
            return res.status(200).send({
                message: "Password successfully updated"
            });
   } catch (error) {
    console.log(error)
   }
 })


export { route };
