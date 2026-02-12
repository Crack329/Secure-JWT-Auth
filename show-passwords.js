const sqlite3 = require('sqlite3');
const db = new sqlite3.Database('./app.db');
db.all("SELECT * FROM users", [], (err, rows) => {
    if (err) throw err;
    console.log('='.repeat(50));
    console.log('PLAINTEXT PASSWORDS FOUND:');
    console.log('='.repeat(50));
    rows.forEach(row => {
        console.log(`Username: ${row.username} | Password: ${row.password} | Email: ${row.email}`);
    });
    console.log('='.repeat(50));
});
db.close();