import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { Box, Button, TextField, Typography } from '@mui/material';
import { useDispatch} from 'react-redux'
import { authActions } from '../store'
const Login = () => {
    const dispatch = useDispatch();
    const history = useNavigate();
    const [inputs, setInputs] = useState({
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
        const res = await axios.post('http://localhost:5000/api/login',{
            email: inputs.email,
            password: inputs.password
        }).catch((err)=>console.log(err))
        const data = await res.data;
        console.log(data);
        return data
    }
    const handleSubmit = (e) => {
        e.preventDefault();
        sendRequest().then(()=>dispatch(authActions.login())).then(()=> history('/user'))
    };
  return (
    <div>
        <form onSubmit={handleSubmit}>
            <Box marginLeft='auto' marginRight='auto'  width={300} display='flex' flexDirection='column' justifyContent='center' alignItems='center'>
                <Typography variant='h4'>Login</Typography>
                <TextField name='email' onChange={handleChange} type='email' value={inputs.email} margin='normal' variant='outlined' placeholder='Email'/>
                <TextField name='password' onChange={handleChange} type='password' value={inputs.password} margin='normal' variant='outlined' placeholder='Password'/>
                <Button variant='contained' type='submit'>Login</Button>
            </Box>
        </form>
    </div>
  )
}


export default Login