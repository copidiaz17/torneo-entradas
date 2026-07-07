import { DataTypes } from 'sequelize'
import { sequelize } from '../database.js'

// Registro de cada visita a la landing (para el contador del panel).
const Visita = sequelize.define('Visita', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  ip: { type: DataTypes.STRING, allowNull: true },
}, {
  tableName: 'visitas',
  timestamps: true, // createdAt = cuándo entró
})

export default Visita
