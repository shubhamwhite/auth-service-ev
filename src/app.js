const express = require('express')
const app = express()
const cors = require('cors')
const cookieParser = require('cookie-parser')
const path = require('path')

const corsOptions = {
  origin: 'http://localhost:5173',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}

// Middleware
app.set('trust proxy', true)
app.use(cors(corsOptions))
app.use(cookieParser())
app.use(express.json())

app.use(express.urlencoded({ extended: true }))
app.use(
  '/api/v1/uploads',
  express.static(path.join(__dirname, '/uploads'))
)
app.set('view engine', 'ejs')
app.set('views', path.join(__dirname, 'views'))

app.use('/', require('./routes/auth.route'))
app.use('/company', require('./routes/company.routes'))

app.get('/auth-service', (req, res) => {
  res.send('auth service up and running!')
})

module.exports = app
