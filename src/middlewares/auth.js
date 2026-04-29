const verificarToken = (req, res, next) => {
    const token = req.headers.authorization;
    if (!token) return res.status(401).json({ msg: 'Token faltante' });

    try {
    const decoded = jwt.verify(token, 'secreto_super_seguro');
    req.usuario = decoded;
    next();
    } catch (err) {
    res.status(403).json({ msg: 'Token inválido' });
    }
};
module.exports = verificarToken;