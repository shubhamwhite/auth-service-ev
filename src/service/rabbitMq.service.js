const amqp = require('amqplib')
const config = require('../config/')
let channel

async function connectRabbitMQ() {
  const connection = await amqp.connect(config.get('AMQP_URL'))
  channel = await connection.createChannel()
  await channel.assertQueue('emailQueue', { durable: true })
  return channel
}

function getChannel() {
  return channel
}

module.exports = { connectRabbitMQ, getChannel }
