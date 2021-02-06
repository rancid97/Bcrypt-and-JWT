require('dotenv').config()
const express = require('express')
const app = express()
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')

app.use(express.json())

const generateAccessToken = (user) => {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {expiresIn: '120s'})
}

//these should be in your database instead (it will be reset everytime server runs)
let refreshTokens = []
let users = []

//check if user exists
const checkIfInArray = (username, array) => {
    let found = false;
    for(let i = 0; i < users.length; i++){
        if(array[i].username === username){
            found = true;
        }
    }
    return found;
}

//regenerate access token if refresh token is valid
app.post('/token', (req,res) => {
    const refreshToken = req.body.token
    if(refreshToken === null) return res.sendStatus(401)
    if(!refreshTokens.includes(refreshToken)){
        return res.sendStatus(403)
    }
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if(err) return res.sendStatus(403)
        const accessToken = generateAccessToken({username: user.username})
        res.json({accessToken: accessToken})
    })
})
//invalidate your refresh token, you can still use your access token while it's valid, but refresh token is invalidated
app.delete('/logout', (req,res) => {
    refreshTokens = refreshTokens.filter(token => token !== req.body.token)
    res.sendStatus(204)
})

//login with credentials, server checks if given password matches the one in users array (using bcrypt) and grants Jason Web Token
app.post('/login',async (req, res) => {
    const username = req.body.username
    const user = users.find(user => user.username === username)
    if (!user) return res.status(400).send('Cannot find user')
    try{
        if(await bcrypt.compare(req.body.password, user.password)){
            const accessToken = generateAccessToken(user)
            const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET)
            refreshTokens.push(refreshToken)
            res.json({accessToken: accessToken, refreshToken: refreshToken})
        } else {
            res.send('Not allowed')
        }
    } catch {
        res.status(500).send()
    }
})

//register with credentials, server will check if current user exists in users array, then it will encrypt given password with bcrypt
app.post('/register',async (req,res) => {
    const username = req.body.username
    //if no argument is passed to genSalt it will use 10 by default
    const salt = await bcrypt.genSalt()
    const hashedPassword = await bcrypt.hash(req.body.password, salt)
    //console logs for better understanding of what happens here
    console.log(salt)
    console.log(hashedPassword)
    if(checkIfInArray(username, users)) {
        res.send('User already exists')
    } else {
        users.push({username: username, password: hashedPassword})
        res.sendStatus(201)
        console.log(users)
    }
})
app.listen(4000)
