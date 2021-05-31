//Import required packages
const express = require('express')
const dotenv = require('dotenv')
const mongoose = require('mongoose')

//Import Routes
const authRoute = require('./Routes/auth')
const postRoute = require('./Routes/posts')
const { verify } = require('jsonwebtoken')

dotenv.config()
const app = express()

//Middleware
app.use(express.json())

//Route middlewares
app.use('/api/user', authRoute)
app.use(postRoute)

//Connection to Database
mongoose.connect(
  process.env.DB_CONNECT,
  {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  },
  () => console.log('connection established')
)

app.listen(3000, () => console.log('server is running'))
