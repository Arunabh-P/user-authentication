const User = require('../model/User');
const bcrypt = require('bcryptjs'); //for bcrypt password
const jwt = require('jsonwebtoken')
const JWT_SECRET_KEY = 'MyKey'
const signup = async (req,res,next)=>{
    const {name,email,password} =req.body; //instead of req.body.name
    let existingUser;
    try{
        existingUser = await User.findOne({email:email})//if there is another email
    }catch(err){
        console.log(err);
    }
    if(existingUser){
        return res.status(400).json({message: "User already exists! Login Instead"})
    }
    const hashedPassword = bcrypt.hashSync(password); //synchornus way of hashing password
    const user = new User({
        name, //name:name
        email, //email:email
        password : hashedPassword //password:password
    });
    try{
        await user.save();
    }catch(err){
        console.log(err);
    }
    return res.status(201).json({message:user})
};
const login = async (req,res,next) => {
    const {email,password} = req.body
    let existingUser;
    try{
        existingUser = await User.findOne({email: email})
    }catch(err){
        return new Error(err)
    }
    if(!existingUser){
        return res.status(400).json({message:"User not found! Signup Please"})
    }
    const isPasswordCorrect = bcrypt.compareSync(password,existingUser.password);
    if(!isPasswordCorrect){
        return res.status(400).json({message:'Invalid Email / Password'})
    }
    const token =  jwt.sign({id:existingUser._id},JWT_SECRET_KEY,{
        expiresIn:"1hr"
    })

    return res.status(200)
    .json({message:'Successfully LoggedIn',user:existingUser,token})
}
const verifyToken = (req,res,next)=>{
   const headers = req.headers[`authorization`];
   const token = headers.split(" ")[1];
   if(!token){
       res.status(404).json({message:'No token found!'})
   }
   jwt.verify(String(token),JWT_SECRET_KEY,(err,user)=>{
       if(err){
           return res.status(400).json({message:'Invalid Token!'})
       }
       console.log(user.id);
   })
}
exports.signup = signup;
exports.login = login;
exports.verifyToken = verifyToken