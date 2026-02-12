const sqlite3 = require('sqlite3');
const bcrypt = require('bcrypt');
const db = new sqlite3.Database('./app.db');

console.log('='.repeat(60));
console.log('🔍 DATABASE DIAGNOSTIC TOOL');
console.log('='.repeat(60));

// Check if database file exists
const fs = require('fs');
if (fs.existsSync('./app.db')) {
    console.log('📁 Database file: app.db ✓');
} else {
    console.log('❌ Database file not found!');
}

// Check users table
db.get("SELECT name FROM sqlite_master WHERE type='table' AND name='users'", (err, table) => {
    if (err) {
        console.log('❌ Error checking table:', err.message);
        return;
    }
    
    if (!table) {
        console.log('❌ Users table does NOT exist!');
        console.log('🔄 Please restart server to create database');
        db.close();
        return;
    }
    
    console.log('✅ Users table exists');
    
    // Count users
    db.get("SELECT COUNT(*) as count FROM users", (err, result) => {
        if (err) {
            console.log('❌ Error counting users:', err.message);
        } else {
            console.log(`👥 Total users in database: ${result.count}`);
        }
        
        // Get all users
        db.all("SELECT id, username, email, password FROM users", [], async (err, users) => {
            if (err) {
                console.log('❌ Error fetching users:', err.message);
                db.close();
                return;
            }
            
            if (users.length === 0) {
                console.log('❌ No users found in database!');
                db.close();
                return;
            }
            
            console.log('\n📋 USER LIST:');
            console.log('-'.repeat(60));
            
            for (const user of users) {
                console.log(`\n👤 Username: ${user.username}`);
                console.log(`📧 Email: ${user.email}`);
                console.log(`🔑 Password hash: ${user.password.substring(0, 30)}...`);
                
                // Test password for admin
                if (user.username === 'admin') {
                    const testPassword = 'admin123';
                    const match = await bcrypt.compare(testPassword, user.password);
                    console.log(`🔐 Testing password '${testPassword}': ${match ? '✅ MATCH' : '❌ NO MATCH'}`);
                    
                    if (!match) {
                        console.log('   ⚠️  Password mismatch! Creating corrected hash...');
                        const newHash = await bcrypt.hash('admin123', 12);
                        console.log(`   ✅ New hash created: ${newHash.substring(0, 30)}...`);
                        
                        // Update the password
                        db.run("UPDATE users SET password = ? WHERE username = ?", 
                            [newHash, 'admin'], 
                            function(err) {
                                if (err) {
                                    console.log(`   ❌ Update failed: ${err.message}`);
                                } else {
                                    console.log(`   ✅ Password updated successfully!`);
                                }
                            }
                        );
                    }
                }
                
                // Test password for john
                if (user.username === 'john') {
                    const testPassword = 'password123';
                    const match = await bcrypt.compare(testPassword, user.password);
                    console.log(`🔐 Testing password '${testPassword}': ${match ? '✅ MATCH' : '❌ NO MATCH'}`);
                }
            }
            
            console.log('\n' + '='.repeat(60));
            console.log('🏁 Diagnostic complete');
            console.log('='.repeat(60));
            
            db.close();
        });
    });
});