const express = require('express');
const mongoose = require('mongoose')
const router = require ("./routes/user.routes")
const app = express()
app.use(express.json())
app.use('/api',router)
mongoose.connect("mongodb+srv://admin:pmF33eDtKhCnqVO9@cluster0.jpzmy.mongodb.net/work?retryWrites=true&w=majority").then(()=>{
    app.listen(5000)
    console.log("Data base is connected! Listening to localhost 5000");
}).catch((err)=>
console.log(err))
//pmF33eDtKhCnqVO9