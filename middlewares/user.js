import { userModel } from "../Database/user.js";
import validator from "email-validator";
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';
dotenv.config();


const findUser= async( userModel,email ) =>{
   console.log(email)
   try {
    let user = await userModel.findOne({email:email})
    console.log(user)
    if(user)return true
    return false
   } catch (error) {
    console.log(error)
   }
}
const checkValidName = (name) => {
    if (name.length === 0 || name.length < 3) return false
    return true
};

const validateEmail = (email) => {
    if (email.length === 0) return false
    return validator.validate(email);
};

const validatePassword = (password) => {
    if (password.length === 0) return false
    let passwordRegex = /^(?=.*\d)(?=.*[!@#$%^&*])(?=.*[a-z])(?=.*[A-Z]).{8,}$/;
    return (passwordRegex.test(password));
}

const comparePassword = (password, secondPassword) => bcrypt.compare(password, secondPassword)

const varifyToken = (token, SIGN) => jwt.verify(token, SIGN)

const generateToken = (SIGN, user) => {
    let token =  jwt.sign({
        name: user.name,
        email: user.email,
    }, SIGN, { expiresIn: '30m' })
    return token
}
let signUpMiddleware  = (userModel) =>[
        async(req, res, next) => {
            console.log(userModel)
          try {
            
              if(!checkValidName(req.body.userinfo.name)){
                return res.status(400).send({
                    error: "Please enter valid name"
                });
              }
           
          } catch (error) {
            console.log(error)
          }
          next();
        },
        (req, res, next) => {
            try {
                if(!validateEmail(req.body.userinfo.email)){
                    return res.status(400).send({
                        error: "Please enter valid email"
                    }); 
                }
                next();
            } catch (error) {
                console.log(error)
            }
        }, (req, res, next) => {
             try {
                 if(!validatePassword(req.body.userinfo.password)){
                    return res.status(400).send({
                        error: "Please enter valid password"
                    }); 
                 }
               next();
             } catch (error) {
                console.log(error)
             }
        },
        async(req,res,next) => {
            try {
                let result = await findUser(userModel,req.body.userinfo.email)
                if(result){
                return res.status(400).send({
                    error: "User Exists"
                }); 
            }
            
            next();
            } catch (error) {
                console.log(error)
            }
        }
    ]



const signInMiddleware = (userModel,SIGN) =>[
    (req, res, next) => {
        try {
            if(!validateEmail(req.body.userinfo.email)){
                return res.status(400).send({
                    error: "Please enter valid email"
                }); 
            }
            next();
        } catch (error) {
            console.log(error)
        }
    },
    (req, res, next) => {
        try {
            if(!validatePassword(req.body.userinfo.password)){
               return res.status(400).send({
                   error: "Please enter valid password"
               }); 
            }
          next();
        } catch (error) {
           console.log(error)
        }
   },
   async(req,res,next) => {
        try {
            let result = await findUser(userModel,req.body.userinfo.email)
                if(!result){
                return res.status(404).send({
                    error: "User not found"
                }); 
            }
            
            next();
        } catch (error) {
            console.log(error)
        }
    },
    (req,res,next) => {
        try {
            let token = generateToken(SIGN,req.body.userinfo)
            req.body.token = token
            next();
        } catch (error) {
            console.log(error)
        }
    }
]


const updatePasswordMiddleware = ( userModel,SIGN ) =>[
    (req, res, next) => {
        try {
            let { password } = req.body.userinfo;
            if(!validatePassword(password)){
               return res.status(400).send({
                   error: "Please enter valid password"
               }); 
            }
          next();
        } catch (error) {
           console.log(error)
        }
   },
    async(req,res,next) =>{
        try {
            let { token } = req.headers;
            if (req.headers.auth) token = req.headers.auth
            if (!varifyToken(token, SIGN)) {
                res.status(400).send({
                    error: "Token Expired"
                });
            }
            next();
        } catch (error) {
            console.log(error)
        }
    }
]

export {signUpMiddleware,signInMiddleware,updatePasswordMiddleware}
