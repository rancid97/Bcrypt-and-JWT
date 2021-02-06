require('dotenv').config()
const express = require('express')
const app = express()
const jwt = require('jsonwebtoken')

app.use(express.json())

const authentication = (req,res,next) => {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]
    if(!token) return res.sendStatus(401)
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403)
        req.user = user
        next()
    })
}

const posts = [{
    username: 'Damian',
    content: 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Suspendisse condimentum condimentum auctor. Phasellus laoreet sed lacus sed tincidunt. Praesent id dolor iaculis, luctus sem vitae.'
},{
    username: 'Andrzej',
    content: 'Maecenas ullamcorper sagittis sapien ut dapibus. Proin finibus velit nulla, non cursus purus maximus non. Vestibulum id tellus accumsan ligula lacinia semper. Proin lacinia lectus.'
}]

app.get('/posts', authentication, (req,res) => {
    res.json(posts.filter(post => post.username === req.user.username))
})
app.post('/posts', authentication, (req,res) => {
    posts.push({username: req.body.username, content: req.body.content})
    res.send('Post published')
})

app.listen(3000)
