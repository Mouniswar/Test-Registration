require('dotenv').config({ path: '../.env' });
const express = require('express');
const router = express.Router();
const db = require('../db/mongodb');
const {validationResult,check, query } = require('express-validator');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const twilio = require('twilio')(process.env.TWILIO_ACCOUNT_SID,process.env.TWILIO_AUTH_TOKEN);
const sgMail = require('@sendgrid/mail');

let collectionName = 'users';



router.post('/api/register',[
    check('signUpType').notEmpty().withMessage('signUpType is missing'),
    check('firstName').notEmpty().trim().withMessage('First Name is missing'),
    check('lastName').notEmpty().trim().withMessage('Last Name is missing'),
    check('countryCode').notEmpty().withMessage('Country code is missing'),
    check('email').optional().isEmail().withMessage('Email is invalid'),
    check('phoneNumber').optional().isLength(10).withMessage('Phone number must have 10 digits'),
    check('username').notEmpty().withMessage('username is missing'),
    check('password').notEmpty().withMessage('password is missing')
],(req,res) => {
    var errors = validationResult(req);
    const errorsArray = errors.errors;
    console.log("errors Array ---",errorsArray);

    if (Array.isArray(errorsArray) && errorsArray.length > 0) {
        console.log("Entered....");
        return res.status(422).send({
            code: 422,
            message: errorsArray[0].msg
        }); 
    }

    let data = req.body;

    function checkUsername() {
        return new Promise((resolve,reject) => {
            let condition = {
                "username":req.body.username
            }

            console.log("Condition in username---",condition);

            db.getDb().collection(collectionName).find(condition).toArray((err,result) => {
                console.log("...........Data from query..",result);
                if(err) {
                    return reject({
                        code:500,
                        message: 'Error While Querying the Database'
                    })
                }
                else if(Array.isArray(result) && result.length > 0) {
                    console.log("into elif....");
                    const characters ='0123456789';
                    let usernames = [];
                    function generateString(length) {
                        let result = '';
                        const charactersLength = characters.length;
                        for ( let i = 0; i < length; i++ ) {
                            result += characters.charAt(Math.floor(Math.random() * charactersLength));
                        }

                        return result;
                    }

                    function generateUsernames() {
                        for(let i = 0; i < 3; i++) {
                            const result = generateString(2);
                            usernames.push(req.body.username.concat(result).trim())
                            console.log("Usernames....",result);
                            console.log(usernames);
                        }
                    }

                    generateUsernames();

                    return reject({
                        code:409,
                        message:'Username already taken.',
                        data:usernames
                    })
                }
                return resolve()
            })
        }) 
    }

    function checkPhoneNumberOrEmail() {
        console.log("intoooo phone r email");
        return new Promise((resolve,reject) => {
            var condition;
            if(req.body.phoneNumber) {
                condition = {
                    "phoneNumber":req.body.phoneNumber
                }
            }

            else if(req.body.email) {
                condition = {
                    "email":req.body.email
                }
            }

            console.log("Condition ---",condition);

            db.getDb().collection(collectionName).find(condition).toArray((err,result) => {
                console.log("result in phone r email",result);
                if(err) {
                    return reject({
                        code:500,
                        message:'Error While Querying Database'
                    })
                }
                else if(Array.isArray(result) && result.length > 0) {
                    return reject({
                        code:409,
                        message: 'Email or Phone Number already taken.'
                    })
                }
                return resolve();
            })
        })
    }

    function register() {
        console.log("into register.....");
        return new Promise((resolve,reject) => {
            let data = req.body;
            const hashedPassword = bcrypt.hashSync(req.body.password,8);
            delete data.password;
            data['password']= hashedPassword;
      
            db.getDb().collection(collectionName).insertOne(data, (err,result) => {
                console.log("Result........innnnnnn reg",result);
                console.log("Result ...",result);
                if(err) {
                    return reject({
                        code:500,
                        message:'Error While Saving into database..'
                    })
                }

                const token = jwt.sign(data, 'Secret')
                data['token'] = token;
        
                return resolve({
                    code:201,
                    message:'Success',
                    data
                });
            })
        })
    }


    checkUsername()
        .then(checkPhoneNumberOrEmail)
        .then(register)
        .then((data) => {
            console.log("Data....",data);
            return res.status(data.code).send(data);
        })
        .catch((e) => {
            return res.status(e.code).send(e)
        })

})

router.post('/api/sendVerifyCodeToPhone',[
    check('countryCode').notEmpty().withMessage('Country Code is missing'),
    check('phoneNumber').notEmpty().withMessage('Phone number is missing').isLength(10).withMessage('Phone number must have 10 digits')
],(req,res) => {
    var errors = validationResult(req);
    const errorsArray = errors.errors;
    console.log("errors Array ---",errorsArray);

    if (Array.isArray(errorsArray) && errorsArray.length > 0) {
        console.log("Entered....");
        return res.status(422).send({
            code: 422,
            message: errorsArray[0].msg
        }); 
    }

    function checkPhoneNumber() {
        return new Promise((resolve,reject) => {
            let condition = {
                "phoneNumber":req.body.phoneNumber
            }

            console.log("Condition ...",condition);

            db.getDb().collection(collectionName).find(condition).toArray((err,data) => {
                console.log("Result....",data);
                if(err) {
                    return reject({
                        code:500,
                        message:'Error While Querying the Database'
                    })
                }
                else if(data.length === 0) {
                    return reject({
                        code: 200,
                        message:'Phone number not exists'
                    })
                }
                return resolve();
            })
        })
    }

    function sendVerificationCode() {
        return new Promise((resolve,reject) => {
            let otpCollection = 'otp';

            let otp = crypto.randomInt(0,1000000);
            console.log("OTP IS ",otp);

            let data = {
                "otp": String(otp),
                "phoneNumber": req.body.phoneNumber
            }

            db.getDb().collection(otpCollection).insertOne(data,(err, result) => {
                if(err) {
                    return reject({
                        code:500,
                        message:'Error While Saving into database..'
                    })
                }

                console.log("Successfully inserted into database....");

                let fullPhoneNumber = `${req.body.countryCode}${req.body.phoneNumber}`;
                twilio.messages.create({
                    body: `Your Verification Code is ${otp}`,
                    from:'+1 507 698 1704',
                    to:fullPhoneNumber
                }).then((data) => {
                    return resolve({
                        code:200,
                        message:'Verification Code sent'
                    })
                })
                .catch((e) => {
                    return reject({
                        code:500,
                        message: `Error, ${e}`
                    })
                })
            })
        })
    }

    checkPhoneNumber()
        .then(sendVerificationCode)
        .then((data) => {
            return res.status(200).send(data)
        })
        .catch((e) => {
            return res.status(e.code).send(e)
        })

})

router.post('/api/verifyPhone',[
    check('otp').notEmpty().withMessage('OTP is missing').isLength(6).withMessage('OTP must have 6 digits.'),
    check('phoneNumber').notEmpty().withMessage('Phone number is missing').isLength(10).withMessage('Phone number must have 10 digits')
],(req,res) => {
    var errors = validationResult(req);
    const errorsArray = errors.errors;
    console.log("errors Array ---",errorsArray);

    if (Array.isArray(errorsArray) && errorsArray.length > 0) {
        console.log("Entered....");
        return res.status(422).send({
            code: 422,
            message: errorsArray[0].msg
        }); 
    }

    let otpCollection = 'otp';
    function verifyOTP() {
        return new Promise((resolve,reject) => {
            let condition = {
                "otp":req.body.otp,
                "phoneNumber":req.body.phoneNumber
            }

            console.log("Condition....",condition);

            db.getDb().collection(otpCollection).find(condition).toArray((err, data) => {
                console.log("Data....",data);
                if(err) {
                    return reject({
                        code: 500,
                        message:'Error While Querying the Database'
                    })
                } else if(data.length === 0) {
                    return reject({
                        code:400,
                        message: 'OTP is invalid'
                    })
                } else if(Array.isArray(data) && data.length !== 0) {
                    return resolve();
                }
            })
        })
    }

    function updateDocument() {
        return new Promise((resolve,reject) => {
            let updateCondition = {
                phoneNumber: String(req.body.phoneNumber)
            }

            console.log("Condition.....",updateCondition);

            db.getDb().collection(collectionName).updateOne(updateCondition,{$set:{"phoneVerified":true}})
                .then((docs) =>  {
                    console.log("Updated document.....",docs);

                    return resolve({
                        code:200,
                        message:'OTP verified'
                    })
                })
                .catch((e) => {
                    return reject({
                        code:500,
                        message:'Error while updating the document'
                    })
                })
            
        })
    }

    verifyOTP()
        .then(updateDocument)
        .then((data) => {
            return res.status(data.code).send(data)
        })
        .catch((e) => {
            return res.status(e.code).send(e)
        })
})

router.post('/api/sendVerificationCodeEmail',[
    check('email').notEmpty().withMessage('Email is missing').isEmail().withMessage('Email is invalid')
],(req,res) => {
    var errors = validationResult(req);
    const errorsArray = errors.errors;
    console.log("errors Array ---",errorsArray);

    if (Array.isArray(errorsArray) && errorsArray.length > 0) {
        console.log("Entered....");
        return res.status(422).send({
            code: 422,
            message: errorsArray[0].msg
        }); 
    }
    function checkEmailExists() {
        console.log("Enterinng into email check.....");
        return new Promise((resolve,reject) => {
            let condition = {
                email: req.body.email
            }

            console.log("Con....",condition);

            db.getDb().collection(collectionName).find(condition).toArray((err,docs) => {
                console.log("Email docs...",docs);
                if(err) {
                    return reject({
                        code:500,
                        message:'Error While Querying Database..'
                    })
                }
                else if(docs.length === 0) {
                    return reject({
                        code:400,
                        message: 'Email not exists...'
                    })
                } else if(Array.isArray(docs) && docs.length !== 0) {
                    return resolve();
                }
            }) 
        })
    }

    function sendVerificationEmail() {
        console.log("veriiiiifi email......");
        return new Promise((resolve,reject) => {
            let updateCondition = {
                email: req.body.email
            }

            console.log("Update condition.....",updateCondition);
            const verificationToken = jwt.sign({email:req.body.email.trim()},'Secret',{expiresIn:'1h'});
            console.log("veif token",verificationToken);
            const verificationCode = crypto.randomInt(0,1000000);
            console.log("code.....", verificationCode);
            db.getDb().collection(collectionName).updateOne(updateCondition,{$set:{
                "verificationToken":verificationToken,
                "verificationCode": verificationCode
            }},(err, docs) => {
                console.log("Docs......",docs);
                if(err) {
                    return reject({
                        code:500,
                        message:'Error while updating the db..'
                    })
                }   
                sgMail.setApiKey(process.env.SENDGRID_API_KEY);
                const msg = {
                    to: req.body.email.trim(),
                    from: process.env.SENDGRID_FROM, // Change to your verified sender
                    subject: 'Verification Code For your Account',
                    html: `<p> Please Verify your email by clicking on below link or Enter Verification code below</p><br />
                    <p>Your Verification Code is ${verificationCode}</p><br />` + 
                   `<a href=${process.env.HOSTNAME}:${process.env.PORT}/api/verifyEmail?token=${verificationToken}&code=${verificationCode}>Click Here to verify your email</a>`,
                  }

                  console.log("Email message....",msg);

                  sgMail.send(msg)
                    .then((data) => {
                        console.log("SGgggg",data);
                        return resolve({
                            code:200,
                            message:'Verification code sent to your Email'
                        })
                    })
                    .catch((e) => {
                        console.log("Errroe",e);
                        return reject({
                            code:500,
                            message:'Error while sending email',
                            error:e
                        })
                    }) 
            })
        })
    }

    checkEmailExists()
        .then(sendVerificationEmail)
        .then((data) => {
            return res.status(data.code).send(data)
        })
        .catch((e) => {
            return res.status(e.code).send(e)
        })
})


router.post('/api/verifyEmail',[
    query('code').notEmpty().withMessage('Code is missing').isLength(6).withMessage('Verification code must contain 6 digits'),
    query('token').notEmpty().withMessage('Please provide token')
],(req,res) => {
    var errors = validationResult(req);
    const errorsArray = errors.errors;
    console.log("errors Array ---",errorsArray);

    if (Array.isArray(errorsArray) && errorsArray.length > 0) {
        console.log("Entered....");
        return res.status(422).send({
            code: 422,
            message: errorsArray[0].msg
        }); 
    }

    const token = req.query.token;
    const code = req.query.code;

    function verifyCode() {
        return new Promise((resolve,reject) => {
            let condition = {
                "verificationToken":token,
                "verificationCode": parseInt(code)
            }

            console.log("Condition....",condition);

            db.getDb().collection(collectionName).find(condition).toArray((err, data) => {
                console.log("Data....",data);
                if(err) {
                    return reject({
                        code: 500,
                        message:'Error While Querying the Database'
                    })
                } else if(data.length === 0) {
                    return reject({
                        code:400,
                        message: 'Verification code is invalid'
                    })
                } else if(Array.isArray(data) && data.length !== 0) {
                    return resolve();
                }
            })
        })
    }

    function updateDocumentMongo() {
        console.log("Entering into ..... mongoo...");
        return new Promise((resolve,reject) => {
            let updatecondition = {
                "verificationToken":token,
                "verificationCode": parseInt(code)
            }

            console.log("condiiii",updatecondition);

            db.getDb().collection(collectionName).updateOne(updatecondition, {
                $set:{
                    emailVerified:true
                },
                $unset: {
                    verificationCode:'',
                    verificationToken:''
                }
            }, (err, docs) => {
                console.log("Docs.....",docs);
                if(err) {
                    return reject({
                        code:500,
                        message:'Error while updating the db'
                    })
                }

                return resolve({
                    code:200,
                    message:'Email Verified.'
                })
            })
        })
    }

    verifyCode()
        .then(updateDocumentMongo)
        .then((data) => {
            return res.status(data.code).send(data)
        })
        .catch((e) => {
            return res.status(e.code).send(e)
        })
})

module.exports = router;