const monk = require('monk');
const db = monk('localhost/auth-for-users');
module.exports= db;
