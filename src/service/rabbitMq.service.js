const amqp = require('amqplib')

let channel

async function connectRabbitMQ() {
  const connection = await amqp.connect('amqp://127.0.0.1')
  channel = await connection.createChannel()
  await channel.assertQueue('emailQueue', { durable: true })
  return channel
}

function getChannel() {
  return channel
}

module.exports = { connectRabbitMQ, getChannel }
