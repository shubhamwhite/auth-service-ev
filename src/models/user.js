'use strict'
const { Model, DataTypes } = require('sequelize')

module.exports = (sequelize) => {
  class User extends Model {
    static associate() {
      // define associations here if any
    }
  }

  User.init(
    {
      id: {
        type: DataTypes.INTEGER,
        autoIncrement: true,
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

      // NEW role field
      role: {
        type: DataTypes.ENUM('user', 'company', 'admin'),
        allowNull: false,
        defaultValue: 'user'
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
