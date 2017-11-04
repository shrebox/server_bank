var express = require('express');
var bodyParser = require('body-parser');
var passwordHash = require('password-hash');
var _ = require('lodash');
var jwt = require('jsonwebtoken');
var Response = require('./responses/response.js');
var fs = require('fs');
const nodemailer = require('nodemailer');

var crypto = require("crypto");
var path = require("path");

var {mongoose} = require('./db/mongoose.js');

var {CustomerInfo} = require('./models/customer_info.js');
var {EmployeeInfo} = require('./models/employee_info.js');
var {Transaction} = require('./models/transaction.js');
var {BankRequest} = require('./models/bank_request.js');
var {CreditDebitRequest} = require('./models/credit_debit.js');
var {CustomerRequest} = require('./models/customer_request.js');
var {OTP} = require('./models/OTP.js');

var {verify_customer,verify_employee} = require('./auth/verify.js');

var encryptStringWithRsaPublicKey = function(toEncrypt, relativeOrAbsolutePathToPublicKey) {
    var absolutePath = path.resolve(relativeOrAbsolutePathToPublicKey);
    var publicKey = fs.readFileSync(absolutePath, "utf8");
    var buffer = new Buffer(toEncrypt);
    var encrypted = crypto.publicEncrypt(publicKey, buffer);
    return encrypted.toString("base64");
};

var decryptStringWithRsaPrivateKey = function(toDecrypt, relativeOrAbsolutePathtoPrivateKey) {
    var absolutePath = path.resolve(relativeOrAbsolutePathtoPrivateKey);
    var privateKey = fs.readFileSync(absolutePath, "utf8");
    var buffer = new Buffer(toDecrypt, "base64");
    var decrypted = crypto.privateDecrypt(privateKey, buffer);
    return decrypted.toString("utf8");
};

var salt = 'hfhfhioe';

var {ObjectId} = require('mongodb');

var app = express();

const port = process.env.PORT || 3000;

app.use(bodyParser.json());

app.post('/customer/login',(req,res)=>{
    var customer = _.pick(req.body,['login_id','password']);

    CustomerInfo.findOne({login_id:customer.login_id}).then((doc)=>{
        if(!doc){

            res.send({response:Response.NOT_FOUND});
        }else{

            if(passwordHash.verify(customer.password,doc.password)){
                var sendObj = _.pick(doc,['firstName','lastName','accountType','balance','accepted']);
                sendObj.response = Response.SUCCESS;

                fs.appendFile('./log.txt','\n' + (new Date()).toString() + '\nLogged in ' + customer.login_id,function(err){
                    if(err)
                        console.log(err);
                    else
                        console.log("saved");
                });

                doc.generateSessId().then((token)=>{
                    sendObj.sessId = token.sessID;
                    res.send(sendObj);
                }).catch((e)=>{
                    res.send({response:Response.ERROR});
                });
                
            }else{
                res.send({response:Response.WRONG_PASSWORD});
            }
        }
    }).catch((e)=>{
        res.send({response:Response.ERROR});
    });

});

app.post('/customer/signup',(req,res)=>{

    var customer = _.pick(req.body,['login_id','password','firstName','lastName','accountType','email','question','answer','phone']);

    customer.password = passwordHash.generate(customer.password);


    var raw_info = _.pick(customer,['login_id','password','firstName','lastName','accountType','email','question','answer','phone']);

    raw_info.accepted = false;
    raw_info.balance = 0;
            
        CustomerInfo.findOne({
            login_id: raw_info.login_id
        },function(err,doc){
            if(!doc || err){

                    var customerInfo = new CustomerInfo(raw_info);

                    customerInfo.save().then(()=>{

                        res.send({response:Response.SUCCESS});

                    }).catch((e)=>{
                        console.log(e);
                        res.send({response:Response.ERROR});
                    });
            }else{
                    res.send({response:Response.ACCOUNT_ALREADY_REGISTERED});
            }
        });
  
});

//Generate OTP
// (sessId)   Object: {email}
app.get('/otp',(req,res)=>{
    jwt.verify(req.header('sessId'),salt,function(err,decoded){
        if(!decoded || err){
            res.send({response:Response.NOT_AUTHORISED});
        }else{
            CustomerInfo.findOne({
                login_id: decoded.login_id
            }).then((info)=>{
                var EMAIL = info.email;

                var temp = Math.floor(Math.random()*10000 + 1000);

                var raw_entry = {
                    email: EMAIL,
                    otp: temp
                };

                var entry = new OTP(raw_entry);

                OTP.remove({email: EMAIL},function(err){
                    if(err){
                        res.send({response:Response.ERROR});
                    }
                });

                nodemailer.createTestAccount((err, account) => {
                    var otp = temp;
                    let transporter = nodemailer.createTransport({
                        host: 'smtp.gmail.com',
                        port: 465,
                        secure: true,
                        auth: {
                            user: 'barishkhandelwal1010@gmail.com', // generated ethereal user
                            pass: '14JAN1994'  // generated ethereal password
                        }
                    });

                    let mailOptions = {
                        from: 'barishkhandelwal1010@gmail.com', // sender address
                        to: EMAIL, // list of receivers
                        subject: 'OTP From FCS Bank', // Subject line
                        text: otp.toString(), // plain text body
                    };


                    transporter.sendMail(mailOptions, (error, info) => {
                        if (error) {
                            return console.log(error);
                        }else{
                            console.log('Email sent: ' + info.response);
                        }
                        
                    });
                });

                entry.save().then(()=>{
                    res.send({response:Response.SUCCESS});
                }).catch((e)=>{
                    console.log(e);
                    res.send({response:Response.ERROR});
                });
            });

            
        }
    });

    
});
/*
    Object:{destination_id,amount,otp}
*/
app.post('/customer/makeTransaction',verify_customer,(req,res)=>{
    jwt.verify(req.header('sessId'),salt,function(err,decoded){
        if(!decoded || err){
            res.send({response:Response.NOT_AUTHORISED});
        }else{
            CustomerInfo.findOne({
                login_id: decoded.login_id
            }).then((info)=>{
                OTP.findOne({
                    email:info.email,
                    otp: req.body.otp
                }).then((temp_OTP)=>{
                    
                    console.log(temp_OTP.otp);
                    
                    CustomerInfo.findOne({
                        login_id:decoded.login_id
                    }).then((customer)=>{
                        var raw_tran = _.pick(req.body,['destination_id','amount']);
                        
                        if(amount<customer.balance){

                            CustomerInfo.findOne({
                                login_id:raw_tran.destination_id
                            }).then((dest)=>{

                                if(!dest){
                                    res.send({response:Response.NOT_FOUND});
                                }else{
                                    var timestamp = new Date().valueOf();
                            
                                    raw_tran.source_id = customer.login_id;
                                    raw_tran.tran_id = timestamp.toString();

                                    var tran = new Transaction(raw_tran);

                                    tran.save().then(()=>{
                                        var d_new_balance = dest.balance + amount;
                                        var s_new_balance = customer.balance - amount;

                                        CustomerInfo.update({login_id: customer.login_id},{$set: { balance:s_new_balance }},function(err,doc){
                                            if(err){
                                                res.send({response:Response.ERROR});
                                            }else{
                                                
                                                CustomerInfo.update({login_id: dest.login_id},{$set: { balance:d_new_balance }},function(err,doc){
                                                    if(err){
                                                        res.send({response:Response.ERROR});
                                                    }else{
                                                        res.send({response:Response.SUCCESS});
                                                    }
                                                });
                                                
                                                fs.appendFile('./log.txt','\n' + (new Date()).toString() + '\nTransfer money ' + req.body.amount.toString + ' from ' + decoded.login_id + ' to ' + req.body.destination_id ,function(err){
                                                    if(err)
                                                        console.log(err);
                                                    else
                                                        console.log("saved");
                                                });
                                            }
                                        });
                                    });
                                }
                                
                            }).catch((e)=>{
                                res.send({response:Response.ERROR});
                            });

                        }else{
                            res.send({response:Response.NOT_ENOUGH_BALANCE});
                        }

                    }).catch((e)=>{
                        res.send({response:Response.ERROR});
                    });

                }).catch((e)=>{
                    console.log(e);
                    res.send({response:Response.ERROR});
                });
            });
   
        }
    });
});


app.get('/customer/previousTransactions',verify_customer,(req,res)=>{

    jwt.verify(req.header('sessId'),salt,function(err,decoded){
        if(!decoded || err){
            res.send({response:Response.NOT_AUTHORISED});
        }else{

            CustomerInfo.findOne({
                login_id:decoded.login_id
            }).then((customer)=>{

                Transaction.find({
                    source_id: customer.login_id
                }).then((docs)=>{
                    var tr = new Array();
                    for(i=0;i<docs.length;++i){
                        tr.push(_.pick(docs[i],['tran_id','destination_id','amount']));
                    }

                    console.log(tr);
                    res.send(tr);
                }).catch((e)=>{
                    res.send({response:Response.ERROR});
                });

            }).catch((e)=>{
                res.send({response:Response.ERROR});
            });
        }
    });
});

app.get('/customer/view_balance',verify_customer,(req,res)=>{
    jwt.verify(req.header('sessId'),salt,function(err,decoded){
        if(!decoded || err){
            res.send({response:Response.NOT_AUTHORISED});
        }else{

            CustomerInfo.findOne({
                login_id:decoded.login_id
            }).then((customer)=>{

                res.send({
                    response:Response.SUCCESS,
                    balance: customer.balance
                })
            }).catch((e)=>{
                res.send({response:Response.ERROR});
            });
        }
    });
});

//Employee login
app.post('/employee/login',(req,res)=>{
    var employee = _.pick(req.body,['login_id','password']);

    EmployeeInfo.findOne({login_id:employee.login_id}).then((doc)=>{
        if(!doc){

            res.send({response:Response.NOT_FOUND});
        }else{

            if(passwordHash.verify(employee.password,doc.password)){
                var sendObj = _.pick(doc,['firstName','lastName','role']);
                sendObj.response = Response.SUCCESS;

                fs.appendFile('./log.txt',(new Date()).toString() + '\nLogged in ' + doc.login_id,function(err){
                    if(err)
                        console.log(err);
                    else
                        console.log("saved");
                });

                doc.generateSessId().then((token)=>{
                    sendObj.sessId = token.sessID;
                    res.send(sendObj);
                }).catch((e)=>{
                    res.send({response:Response.ERROR});
                });

            }else{
                res.send({response:Response.WRONG_PASSWORD});
            }
        }
    }).catch((e)=>{
        console.log(e);
        res.send({response:Response.ERROR});
    });
});


//Admin routes
app.get('/admin/emplist',verify_employee,(req,res)=>{
    jwt.verify(req.header('sessId'),salt,function(err,decoded){
        if(!decoded || err){
            res.send({response:Response.NOT_AUTHORISED});
        }else{

            EmployeeInfo.findOne({
                login_id:decoded.login_id,
                role:2  //2 for admin
            }).then((employee)=>{

                EmployeeInfo.find({}).then((docs)=>{
                    var tr = new Array();
                    for(i=0;i<docs.length;++i){
                        tr.push(_.pick(docs[i],['login_id','firstName','lastName','phone','role']));
                    }

                    console.log(tr);
                    res.send(tr);
                }).catch((e)=>{
                    res.send({response:Response.ERROR});
                });

            }).catch((e)=>{
                res.send({response:Response.ERROR});
            });
        }
    });
});

app.get('/admin/custlist',verify_employee,(req,res)=>{
    jwt.verify(req.header('sessId'),salt,function(err,decoded){
        if(!decoded || err){
            res.send({response:Response.NOT_AUTHORISED});
        }else{

            EmployeeInfo.findOne({
                login_id:decoded.login_id,
                role:2  //2 for admin
            }).then((employee)=>{

                CustomerInfo.find({}).then((docs)=>{
                    var tr = new Array();
                    for(i=0;i<docs.length;++i){
                        tr.push(_.pick(docs[i],['login_id','firstName','lastName','phone','balance','employee_id']));
                    }

                    console.log(tr);
                    res.send(tr);
                }).catch((e)=>{
                    res.send({response:Response.ERROR});
                });

            }).catch((e)=>{
                res.send({response:Response.ERROR});
            });
        }
    });
});

/*
    Object:{login_id,password,firstName,lastName,phone,role}
*/
app.post('/admin/employee_registration',verify_employee,(req,res)=>{
    jwt.verify(req.header('sessId'),salt,function(err,decoded){
        if(!decoded || err){
            res.send({response:Response.NOT_AUTHORISED});
        }else{

            EmployeeInfo.findOne({
                login_id:decoded.login_id,
                role:2  //2 for admin
            }).then((admin)=>{

                var raw_info = _.pick(req.body,['login_id','password','firstName','lastName','phone','role']);
                raw_info.password = passwordHash.generate(raw_info.password);

                var employeeInfo = new EmployeeInfo(raw_info);

                employeeInfo.save().then(()=>{

                    res.send({response:Response.SUCCESS});
                }).catch((e)=>{
                    res.send({response:Response.ERROR});
                });

            }).catch((e)=>{
                res.send({response:Response.ERROR});
            });
        }
    });
});

/*
    Request: Headers(sessId), Object:{login_id,firstName,lastName,phone,role}
*/
app.post('/admin/modify_employee',verify_employee,(req,res)=>{
    jwt.verify(req.header('sessId'),salt,function(err,decoded){
        if(!decoded || err){
            res.send({response:Response.NOT_AUTHORISED});
        }else{

            EmployeeInfo.findOne({
                login_id:decoded.login_id,
                role:2  //2 for admin
            }).then((admin)=>{

                        EmployeeInfo.update({login_id:req.body.login_id},{$set: { 
                            firstName:req.body.firstName,
                            lastName:req.body.lastName,
                            role:req.body.role,
                            phone:req.body.phone
                        }},function(err,doc){
                            if(err || !doc){
                                res.send({response:Response.ERROR});
                            }else{
                                res.send({response:Response.SUCCESS});
                            }
                        });

            }).catch((e)=>{
                res.send({response:Response.ERROR});
            });
        }
    });
});

/*
    Object:{login_id}
*/
app.post('/admin/delete_employee',verify_employee,(req,res)=>{
    jwt.verify(req.header('sessId'),salt,function(err,decoded){
        if(!decoded || err){
            res.send({response:Response.NOT_AUTHORISED});
        }else{
        
            EmployeeInfo.findOne({
                login_id:decoded.login_id,
                role:2  //2 for admin
            }).then((admin)=>{
                if(admin.login_id===req.body.login_id){
                    req.body.login_id = null;
                    res.send({response:Response.NOT_AUTHORISED});
                }else{

                    EmployeeInfo.remove({login_id:req.body.login_id},function(err){
                        if(err){
                            res.send({response:Response.ERROR});
                        }else{
                            res.send({response:Response.SUCCESS});
                        }
                    }).catch((e)=>{
                        res.send({response:Response.ERROR});
                    });
                }
                

            }).catch((e)=>{
                res.send({response:Response.ERROR});
            });
        }
    });
});

/*
    Object:{accepted:boolean,request_id}
*/
app.post('/admin/modify_customer',verify_employee,(req,res)=>{
    jwt.verify(req.header('sessId'),salt,function(err,decoded){
        if(!decoded || err){
            res.send({response:Response.NOT_AUTHORISED});
        }else{

            EmployeeInfo.findOne({
                login_id:decoded.login_id,
                role:2  //2 for admin
            }).then((admin)=>{

                CustomerRequest.findOne({
                    request_id:req.body.request_id
                }).then((request)=>{

                    if(req.body.accepted===true){

                        CustomerInfo.update({login_id: request.login_id},{$set: { 
                            email: request.email,
                            question: request.question,
                            answer: request.answer,
                            phone: request.phone
                        }},function(err,doc){
                            
                            if(err || !doc){
                                res.send({response:Response.ERROR});
                            }else{
								CustomerRequest.remove({request_id: req.body.request_id},function(err){
									if(err){
										res.send({response:Response.ERROR});
									}else{
										res.send({response:Response.SUCCESS});
									}
								});
                                res.send({response:Response.SUCCESS});
                            }
                        });

                    }else{

                        CustomerRequest.remove({request_id: req.body.request_id},function(err){
                            if(err){
                                res.send({response:Response.ERROR});
                            }else{
                                res.send({response:Response.SUCCESS});
                            }
                        });
                    }
                });
                    

            }).catch((e)=>{
                res.send({response:Response.ERROR});
            });
        }
    });
});

app.get('/admin/modify_customer',verify_employee,(req,res)=>{
    jwt.verify(req.header('sessId'),salt,function(err,decoded){
        if(!decoded || err){
            res.send({response:Response.NOT_AUTHORISED});
        }else{

            EmployeeInfo.findOne({
                login_id:decoded.login_id,
                role:2  //2 for admin
            }).then((admin)=>{

                CustomerRequest.find({}).then((requests)=>{
                    var tr = new Array();
                    for(i=0;i<requests.length;++i){
                        tr.push(_.pick(requests[i],['request_id','login_id','email','question','answer','phone']));
                    }

                    console.log(tr);
                    res.send(tr);
                }).catch((e)=>{
                    res.send({response:Response.ERROR});
                }); 

            }).catch((e)=>{
                res.send({response:Response.ERROR});
            });
        }
    });
});

//Object:{accepted:boolean, login_id}
app.post('/admin/registration_requests/post',verify_employee,(req,res)=>{
    jwt.verify(req.header('sessId'),salt,function(err,decoded){
        if(!decoded || err){
            res.send({response:Response.NOT_AUTHORISED});
        }else{

            EmployeeInfo.findOne({
                login_id:decoded.login_id,
                role:2  //2 for admin
            }).then((admin)=>{

                if(req.body.accepted===true){

                    CustomerInfo.update({login_id: req.body.login_id},{$set: { accepted:true }},function(err,doc){
                        if(err || !doc){
                            res.send({response:Response.ERROR});
                        }else{
                            res.send({response:Response.SUCCESS});
                        }
                    });
                }else{

                    CustomerInfo.remove({login_id:req.body.login_id},function(err){
                        if(err){
                            res.send({response:Response.ERROR});
                        }else{
                            res.send({response:Response.SUCCESS});
                        }
                    });
                }

            }).catch((e)=>{
                res.send({response:Response.ERROR});
            });
        }
    });
});

app.get('/admin/registration_requests/get',verify_employee,(req,res)=>{
    jwt.verify(req.header('sessId'),salt,function(err,decoded){
        if(!decoded || err){
            res.send({response:Response.NOT_AUTHORISED});
        }else{

            EmployeeInfo.findOne({
                login_id:decoded.login_id,
                role:2  //2 for admin
            }).then((admin)=>{

                CustomerInfo.find({
                    accepted: false
                }).then((customers)=>{

                    var tr = new Array();
                    for(i=0;i<customers.length;++i){
                        tr.push(_.pick(customers[i],['login_id','firstName','lastName','phone','accountType']));
                    }

                    console.log(tr);
                    res.send(tr);

                }).catch((e)=>{
                    res.send({response:Response.ERROR});
                });

            }).catch((e)=>{
                res.send({response:Response.ERROR});
            });
        }
    });
});

/* Admin will send authorization request if no employee is assigned to review the external user.
    Object:{login_id}
*/
app.post('/admin/send_auth_request',verify_employee,(req,res)=>{
    jwt.verify(req.header('sessId'),salt,function(err,decoded){
        if(!decoded || err){
            res.send({response:Response.NOT_AUTHORISED});
        }else{

            EmployeeInfo.findOne({
                login_id:decoded.login_id,
                role:2  //2 for admin
            }).then((admin)=>{

                CustomerInfo.findOne({
                    login_id: req.body.login_id
                }).then((customer)=>{

                    if(!customer.employee_id){
                        var timestamp = new Date().valueOf();
                        var request = {
                            request_id: timestamp.toString(),
                            login_id: customer.login_id
                        }

                        var bank_request = new BankRequest(request);
                        bank_request.save().then(()=>{
                            res.send({response:Response.SUCCESS});
                        }).catch((e)=>{
                            res.send({response:Response.ERROR});
                        });
                    }
                }).catch((e)=>{
                    res.send({response:Response.ERROR});
                });

            }).catch((e)=>{
                res.send({response:Response.ERROR});
            });
        }
    });
});

app.get('/admin/unauth_customers',verify_employee,(req,res)=>{
    jwt.verify(req.header('sessId'),salt,function(err,decoded){
        if(!decoded || err){
            res.send({response:Response.NOT_AUTHORISED});
        }else{

            EmployeeInfo.findOne({
                login_id:decoded.login_id,
                role:2  //2 for admin
            }).then((admin)=>{

                CustomerInfo.find({
                    employee_id: null
                }).then((docs)=>{

                    var tr = new Array();
                    for(i=0;i<docs.length;++i){
                        tr.push(_.pick(docs[i],['login_id','firstName','lastName','phone','balance']));
                    }

                    console.log(tr);
                    res.send(tr);
                }).catch((e)=>{
                    res.send({response:Response.ERROR});
                });

            }).catch((e)=>{
                res.send({response:Response.ERROR});
            });
        }
    });
});

app.get('/admin/view_log',verify_employee,(req,res)=>{
    jwt.verify(req.header('sessId'),salt,function(err,decoded){
        if(!decoded || err){
            res.send({response:Response.NOT_AUTHORISED});
        }else{

            EmployeeInfo.findOne({
                login_id:decoded.login_id,
                role:2  //2 for admin
            }).then((admin)=>{

                fs.readFile('./log.txt','utf8',function(err,data){
                    if(err){
                        res.send({
                            response: Response.SUCCESS,
                            content: "Log file not available"
                        });
                    }else{
                        res.send({
                            response: Response.SUCCESS,
                            content: data
                        });
                    }
                });

            }).catch((e)=>{
                res.send({response:Response.ERROR});
            });
        }
    });
});

/*  Customer accepts or rejects the request
    Object: {accepted:boolean,request_id}
*/
app.post('/customer/post_auth_request',verify_customer,(req,res)=>{
    jwt.verify(req.header('sessId'),salt,function(err,decoded){
        if(!decoded || err){
            res.send({response:Response.NOT_AUTHORISED});
        }else{

            CustomerInfo.findOne({
                login_id: decoded.login_id
            }).then((customer)=>{
                if(accepted===true){
                    EmployeeInfo.find({}).then((employees)=>{

                    var index = Math.floor(Math.random() * (employees.length - 0)) + 0;
                    CustomerInfo.update({login_id:customer.login_id},{$set: {employee_id: employees[index].login_id}},function(err,doc){
                            if(err){
                                res.send({response:Response.ERROR});
                            }else{
    
                                BankRequest.remove({login_id: customer.login_id},function(err){
                                    if(err){
                                        res.send({response:Response.ERROR});
                                    }else{
                                        res.send({response:Response.SUCCESS});
                                    }
                                });
                            }
                        });
                    });
                }else{
                    BankRequest.remove({request_id: req.body.request_id},function(err){
                                    if(err){
                                        res.send({response:Response.ERROR});
                                    }else{
                                        res.send({response:Response.SUCCESS});
                                    }
                    });
                }
                

            }).catch((e)=>{
                res.send({response:Response.ERROR});
            });
        }
    });
});

app.get('/customer/get_auth_request',verify_customer,(req,res)=>{
    jwt.verify(req.header('sessId'),salt,function(err,decoded){
        if(!decoded || err){
            res.send({response:Response.NOT_AUTHORISED});
        }else{

            CustomerInfo.findOne({
                login_id: decoded.login_id
            }).then((customer)=>{
                
                BankRequest.findOne({
                    login_id: customer.login_id
                }).then((request)=>{
                    res.send({
                        response: Response.SUCCESS,
                        request_id: request.request_id
                    });
                }).catch((e)=>{
                    res.send({response:Response.ERROR});
                });

            }).catch((e)=>{
                res.send({response:Response.ERROR});
            });
        }
    });
});

//Send details modification Request to administrator
/*
    Object:{login_id,email,question,answer,phone}
*/
app.post('/customer/modify_request',verify_customer,(req,res)=>{
    jwt.verify(req.header('sessId'),salt,function(err,decoded){
        if(!decoded || err){
            res.send({response:Response.NOT_AUTHORISED});
        }else{

            CustomerInfo.findOne({
                login_id: decoded.login_id
            }).then((customer)=>{
                
                var timestamp = new Date().valueOf();

                var raw_request = {
                    request_id:timestamp.toString(),
                    login_id:customer.login_id,
                    email:req.body.email,
                    question:req.body.question,
                    answer:req.body.answer,
                    phone:req.body.phone
                };
                

                var b_request = new CustomerRequest(raw_request);

                b_request.save().then(()=>{
                        res.send({response:Response.SUCCESS});
                }).catch((e)=>{
					//console.log(e);
					res.send({response:Response.ERROR});
				}).catch((e)=>{
                    res.send({response:Response.ERROR});
                });

            }).catch((e)=>{
                res.send({response:Response.ERROR});
            });
        }
    });
});



/*//Customer : Send credit/debit request
Request : Headers(sessId)  Object : {amount,request_type(0-credit,1-debit)}
*/
app.post('/customer/credit_debit_request',verify_customer,(req,res)=>{
    jwt.verify(req.header('sessId'),salt,function(err,decoded){
        if(!decoded || err){
			console.log(doc);
			console.log(err);
            res.send({response:Response.NOT_AUTHORISED});
        }else{

            CustomerInfo.findOne({
                login_id: decoded.login_id
            }).then((customer)=>{
                var timestamp = new Date().valueOf();

                var raw_request = {
                    request_id: customer.login_id.toString() + '$' + timestamp.toString(),
                    login_id: customer.login_id,
                    status:0,
                    amount: req.body.amount,
                    request_type:req.body.request_type
                };


                var b_request = new CreditDebitRequest(raw_request);

                b_request.save().then(()=>{
                        res.send({response:Response.SUCCESS});
                }).catch((e)=>{
                    res.send({response:Response.ERROR});
                });

            }).catch((e)=>{
				console.log(e);
                res.send({response:Response.ERROR});
            });
        }
    });
});


/*//See debit/credit request of authorized user
Request : Headers(sessId)
*/
app.get('/employee/credit_debit_request',verify_employee,(req,res)=>{
    jwt.verify(req.header('sessId'),salt,function(err,decoded){
        if(!decoded || err){
            res.send({response:Response.NOT_AUTHORISED});
        }else{
            
            EmployeeInfo.findOne({
                login_id:decoded.login_id
            }).then((employee)=>{
                
                CustomerInfo.find({
                    employee_id: employee.login_id
                    
                }).then((customers)=>{
                    if(!customers){
                        res.send({response:Response.NOT_AUTHORISED});
                    }else{
						
						for(j=0;j<customers.length;++j){
							var tr = new Array();
							
							CreditDebitRequest.find({
								login_id: customers[j].login_id,
								status:0
							}).then((requests)=>{                           
							  
								for(i=0;i<requests.length;++i){
									tr.push(_.pick(requests[i],['request_id','login_id','amount','request_type']));
								}
								
							}).catch((e)=>{
								res.send({response:Response.ERROR});
							});
							
							res.send(tr);
						}
                        
                    }

                }).catch((e)=>{
					res.send({response:Response.ERROR});
				});

                
            }).catch((e)=>{
                res.send({response:Response.ERROR});
            });
        }
    });
});

/*//Accept or reject request
    Object:{accepted,request_id}
*/
app.post('/employee/credit_debit_request_post',verify_employee,(req,res)=>{
    jwt.verify(req.header('sessId'),salt,function(err,decoded){
        if(!decoded || err){
            res.send({response:Response.NOT_AUTHORISED});
        }else{
            
            EmployeeInfo.findOne({
                login_id:decoded.login_id
            }).then((employee)=>{
                
                CreditDebitRequest.findOne({
                    request_id: req.body.request_id,
                    status:0
                }).then((request)=>{
                    if(accepted===true){
                        CustomerInfo.findOne({
                            login_id: request.login_id
                        }).then((customer)=>{
                            var new_balance = 0;

                            if(request.request_type===1){
                                new_balance = customer.balance - request.amount;
                            }else if(request.request_type===0){
                                new_balance = customer.balance + request.amount;
                            }
                            
                            //if amount to be debited is more than balance then this response will be sent
                            if(new_balance<0){
                                res.send({response:Response.NOT_ENOUGH_BALANCE});
                            }

                            CustomerInfo.update({login_id: customer.login_id},{$set: { balance: new_balance }},function(err,doc){
                                if(err || !doc){
                                    res.send({response:Response.ERROR});
                                }else{
                                    CreditDebitRequest.update({request_id: request.request_id},{$set: { status: 2 }},function(err,doc){
                                        if(err || !doc){
                                            res.send({response:Response.ERROR});
                                        }else{
                                            res.send({response:Response.SUCCESS});
                                        }
                                    });
                                }
                            });

                        }).catch((e)=>{
                            res.send({response:Response.ERROR});
                        });

                    }else{

                        CreditDebitRequest.update({request_id: request.request_id},{$set: { status: 1 }},function(err,doc){
                            if(err || !doc){
                                  res.send({response:Response.ERROR});
                            }else{
                                  res.send({response:Response.SUCCESS});
                            }
                        });
                    }
                    
                });
                
            }).catch((e)=>{
                res.send({response:Response.ERROR});
            });
        }
    });
});


//Employee can view transactions of a customer if he/she is authorised
//Object: {login_id}
app.post('/employee/view_transactions',verify_employee,(req,res)=>{
    jwt.verify(req.header('sessId'),salt,function(err,decoded){
        if(!decoded || err){
            res.send({response:Response.NOT_AUTHORISED});
        }else{
            
            EmployeeInfo.findOne({
                login_id:decoded.login_id
            }).then((employee)=>{
                
                CustomerInfo.findOne({
                    login_id: req.body.login_id
                }).then((customer)=>{
                    if(!customer){
                        res.send({response:Response.NOT_FOUND});
                    }else{

                        Transaction.find({
                            source_id: customer.login_id
                        }).then((docs)=>{
                            var tr = new Array();
                            for(i=0;i<docs.length;++i){
                                if(employee.role>=1 || (employee.role==0 && doc[i].amount<=10000))    //Critical amount = 10000
                                    tr.push(_.pick(docs[i],['tran_id','sourceAccount','destinationAccount','amount']));
                            }

                            

                            Transaction.find({
                                destination_id: customer.login_id
                            }).then((trans)=>{
                                
                                for(i=0;i<trans.length;++i){
                                    if(employee.role>=1 || (employee.role==0 && doc[i].amount<=10000))    //Critical amount = 10000
                                        tr.push(_.pick(trans[i],['tran_id','sourceAccount','destinationAccount','amount']));
                                }

                            }).catch((e)=>{
                                res.send({response:Response.ERROR});
                            });

                            res.send(tr);
                        }).catch((e)=>{
                            res.send({response:Response.ERROR});
                        });
                    }
                }).catch((e)=>{
                    res.send({response:Response.ERROR});
                });

            }).catch((e)=>{
                res.send({response:Response.ERROR});
            });
        }
    });
});

//System_Manager can view transactions of a customer if he/she is authorised
app.get('/manager/credit_debit_request',verify_employee,(req,res)=>{
    jwt.verify(req.header('sessId'),salt,function(err,decoded){
        if(!decoded || err){
            res.send({response:Response.NOT_AUTHORISED});
        }else{
            
            EmployeeInfo.findOne({
                login_id:decoded.login_id,
                role: 1
            }).then((employee)=>{
                if(!employee){
                    res.send({response:Response.NOT_AUTHORISED});
                }

                
                CreditDebitRequest.find({
                            status:0
                }).then((requests)=>{
                            
                            var tr = new Array();
                            for(i=0;i<requests.length;++i){
                                tr.push(_.pick(requests[i],['request_id','login_id','amount','request_type']));
                            }
                            res.send(tr);

                }).catch((e)=>{
					res.send({response:Response.ERROR});
				});
                 

                
            }).catch((e)=>{
                res.send({response:Response.ERROR});
            });
        }
    });
});

/*//Accept or reject request
    Object:{accepted,request_id}
*/
app.post('/manager/credit_debit_request_post',verify_employee,(req,res)=>{
    jwt.verify(req.header('sessId'),salt,function(err,decoded){
        if(!decoded || err){
            res.send({response:Response.NOT_AUTHORISED});
        }else{
            
            EmployeeInfo.findOne({
                login_id:decoded.login_id,
                role: 1
            }).then((employee)=>{
                
                CreditDebitRequest.findOne({
                    request_id: req.body.request_id,
                    status:0
                }).then((request)=>{
                    if(accepted===true){
                        CustomerInfo.findOne({
                            login_id: request.login_id
                        }).then((customer)=>{
                            var new_balance = 0;

                            if(request.request_type===1){
                                new_balance = customer.balance - request.amount;
                            }else if(request.request_type===0){
                                new_balance = customer.balance + request.amount;
                            }
                            //if amount to be debited is more than balance then this response will be sent
                            if(new_balance<0){
                                res.send({response:Response.NOT_ENOUGH_BALANCE});
                            }

                            CustomerInfo.update({login_id: customer.login_id},{$set: { balance: new_balance }},function(err,doc){
                                if(err || !doc){
                                    res.send({response:Response.ERROR});
                                }else{
                                    CreditDebitRequest.update({request_id: request.request_id},{$set: { status: 2 }},function(err,doc){
                                        if(err || !doc){
                                            res.send({response:Response.ERROR});
                                        }else{
                                            res.send({response:Response.SUCCESS});
                                        }
                                    });
                                }
                            });
                        }).catch((e)=>{
							res.send({response:Response.ERROR});
						});
                    }else{

                        CreditDebitRequest.update({request_id: request.request_id},{$set: { status: 1 }},function(err,doc){
                            if(err || !doc){
                                  res.send({response:Response.ERROR});
                            }else{
                                  res.send({response:Response.SUCCESS});
                            }
                        });
                    }
                    
                }).catch((e)=>{
					res.send({response:Response.ERROR});
				});
                
            }).catch((e)=>{
                res.send({response:Response.ERROR});
            });
        }
    });
});

app.listen(port,()=>{
    console.log(`Listening on port ${port}`);
});