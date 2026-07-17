import { DataTypes } from 'sequelize'
import { sequelize } from '../database.js'

// Usuarios del panel: admin (ve ventas), control (escanea en puerta),
// venta (venta y control manual: ve el listado, muestra QR y genera entradas manuales).
const Usuario = sequelize.define('Usuario', {
  id:       { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  usuario:  { type: DataTypes.STRING, allowNull: false, unique: true },
  hash:     { type: DataTypes.STRING, allowNull: false },  // scrypt del password
  salt:     { type: DataTypes.STRING, allowNull: false },
  rol:      { type: DataTypes.ENUM('admin', 'control', 'venta'), allowNull: false },
}, {
  tableName: 'usuarios',
  timestamps: true,
})

export default Usuario
