import { DataTypes } from 'sequelize'
import { sequelize } from '../database.js'

// Una orden de compra de entradas.
const Orden = sequelize.define('Orden', {
  id:        { type: DataTypes.STRING, primaryKey: true },   // 'orden_<uuid>'
  nombre:    { type: DataTypes.STRING, allowNull: false },
  email:     { type: DataTypes.STRING, allowNull: false },
  dni:       { type: DataTypes.STRING, allowNull: false },
  metodo:    { type: DataTypes.STRING, defaultValue: 'mp' },
  cantidad:  { type: DataTypes.INTEGER, allowNull: false },
  subtotal:  { type: DataTypes.INTEGER, allowNull: false },
  cargo:     { type: DataTypes.INTEGER, allowNull: false },
  total:     { type: DataTypes.INTEGER, allowNull: false },
  estado:    { type: DataTypes.ENUM('pendiente', 'pagada'), defaultValue: 'pendiente' },
  paymentId: { type: DataTypes.STRING, allowNull: true },
}, {
  tableName: 'ordenes',
  timestamps: true, // createdAt = fecha de la orden
})

export default Orden
