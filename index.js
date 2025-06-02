const app = require('./src/app')
const config = require('./src/config')
const PORT = config.get('PORT') || 3000
const color = require('./src/helper/color.helper')
const { connectDB } = require('./src/models/index')

app.listen(PORT, async (err) => {
  if (err) {
    color.error('Error starting server:', err)
  } else {
    await connectDB(err) // database connection call
    color.success(`Auth-service running on ${PORT} port number.`) // port connection
  }
})
