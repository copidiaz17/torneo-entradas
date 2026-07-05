// Modelos + asociaciones. Importá siempre desde acá.
import { sequelize } from '../database.js'
import Orden from './Orden.js'
import Entrada from './Entrada.js'

Orden.hasMany(Entrada, { as: 'qrs', foreignKey: 'orden_id', onDelete: 'CASCADE' })
Entrada.belongsTo(Orden, { as: 'orden', foreignKey: 'orden_id' })

export { sequelize, Orden, Entrada }
