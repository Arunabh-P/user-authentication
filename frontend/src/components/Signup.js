import { Box, Button, TextField, Typography } from '@mui/material'
import React, { useState } from 'react'
import axios from 'axios'
import { useNavigate } from 'react-router-dom'

const Signup = () => {
    const history = useNavigate();
    const [inputs, setInputs] = useState({
        name : "",
        email : "",
        password : ""
    })
    const handleChange=(e)=>{
        setInputs(prev =>({
            ...prev,
            [e.target.name]:e.target.value
        }))
    }
    const sendRequest = async () => {
        const res = await axios.post('http://localhost:5000/api/signup',{
            name:inputs.name,
            email: inputs.email,
            password: inputs.password
        }).catch((err)=>console.log(err))
        const data =await res.data;
        return data
    }
    const handleSubmit = (e) => {
        e.preventDefault();
        console.log(inputs);
        //send http request
        sendRequest().then(()=> history('/login'))
    };
  return (
    <div>
        <form onSubmit={handleSubmit}>
            <Box marginLeft='auto' marginRight='auto'  width={300} display='flex' flexDirection='column' justifyContent='center' alignItems='center'>
                <Typography variant='h4'>Signup</Typography>
                <TextField name='name' onChange={handleChange} value={inputs.name} margin='normal' variant='outlined' placeholder='Name'/>
                <TextField name='email' onChange={handleChange} type='email' value={inputs.email} margin='normal' variant='outlined' placeholder='Email'/>
                <TextField name='password' onChange={handleChange} type='password' value={inputs.password} margin='normal' variant='outlined' placeholder='Password'/>
                <Button variant='contained' type='submit'>Signup</Button>
            </Box>
        </form>
    </div>
  )
}

export default Signup