'use strict'
const { Model, DataTypes } = require('sequelize')
const { v4: uuidv4 } = require('uuid') // Optional if you want to generate manually

module.exports = (sequelize) => {
  class User extends Model {
    static associate() {
      // define associations here if any
    }
  }

  User.init(
    {
      id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4, // Sequelize will generate UUID v4
        allowNull: false,
        primaryKey: true
      },
      first_name: {
        type: DataTypes.STRING,
        allowNull: false
      },
      last_name: {
        type: DataTypes.STRING,
        allowNull: false
      },
      email: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true,
        validate: {
          isEmail: true
        }
      },
      password: {
        type: DataTypes.STRING,
        allowNull: false
      },
      is_verified: {
        type: DataTypes.BOOLEAN,
        defaultValue: false
      },
      verification_otp: {
        type: DataTypes.STRING,
        allowNull: true
      },
      otp_expires_at: {
        type: DataTypes.DATE,
        allowNull: true
      },
      profile_image: {
        type: DataTypes.STRING,
        allowNull: true
      },
      google_id: {
        type: DataTypes.STRING,
        allowNull: true,
        unique: true
      },
      login_type: {
        type: DataTypes.ENUM('manual', 'google'),
        allowNull: false,
        defaultValue: 'manual'
      },
      block: {
        type: DataTypes.BOOLEAN,
        defaultValue: false
      },
      role: {
        type: DataTypes.ENUM('user', 'company', 'admin', 'superadmin'),
        allowNull: false,
        defaultValue: 'user'
      },
      ip_address: {
        type: DataTypes.STRING,
        allowNull: true,
        comment: 'IP address during registration or last update'
      },
      last_login_ip: {
        type: DataTypes.STRING,
        allowNull: true,
        comment: 'IP address during the last login'
      },
      user_agent: {
        type: DataTypes.STRING,
        allowNull: true,
        comment: 'User-Agent header string'
      }
    },
    {
      sequelize,
      modelName: 'User',
      timestamps: true
    }
  )

  return User
}
