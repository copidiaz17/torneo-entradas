import { DataTypes } from 'sequelize'
import { sequelize } from '../database.js'

// Una entrada individual (un QR) dentro de una orden.
const Entrada = sequelize.define('Entrada', {
  id:       { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  orden_id: { type: DataTypes.STRING, allowNull: false },
  indice:   { type: DataTypes.INTEGER, allowNull: false },      // 1..cantidad
  codigo:   { type: DataTypes.STRING, allowNull: false },       // contenido firmado del QR (base::sig)
  base:     { type: DataTypes.STRING, allowNull: false },       // "ordenId::indice"
  archivo:  { type: DataTypes.STRING },                         // ruta local del PNG
  url:      { type: DataTypes.STRING },                         // /qrs/<archivo>
  usado:    { type: DataTypes.BOOLEAN, defaultValue: false },   // control de UN SOLO USO en puerta
  usadoEn:  { type: DataTypes.DATE, allowNull: true },
}, {
  tableName: 'entradas',
  timestamps: true,
  indexes: [{ fields: ['base'] }, { fields: ['orden_id'] }],
})

export default Entrada
