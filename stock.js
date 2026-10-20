/**
 * Situação do estoque de um produto (usada pela lista de produtos, pelo aviso
 * de "estoque baixo" e pelo dashboard, para os números baterem em todas as telas).
 *
 *  ok     → acima do nível de alerta (ou produto sem controle de estoque: mínimo 0)
 *  limit  → no limite: do mínimo até mínimo + 20% (pelo menos +1 unidade)
 *  below  → abaixo do mínimo
 *  out    → zerado
 */
const LIMIT_MARGIN = 0.2;

function stockStatus(product) {
  const min = Number(product.minimumStock) || 0;
  const stock = Number(product.stock) || 0;
  if (min <= 0) return 'ok';
  if (stock === 0) return 'out';
  if (stock < min) return 'below';
  return stock <= min + Math.max(1, Math.ceil(min * LIMIT_MARGIN)) ? 'limit' : 'ok';
}

module.exports = { stockStatus };
