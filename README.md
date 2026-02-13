<h1 align="center">🔐 Secure JWT Authentication System</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Security-Hardened-brightgreen" />
  <img src="https://img.shields.io/badge/Auth-JWT-blue" />
  <img src="https://img.shields.io/badge/Passwords-bcrypt-yellow" />
  <img src="https://img.shields.io/badge/Headers-Helmet.js-orange" />
</p>

<hr/>

<h2>📋 Project Overview</h2>

<p>
<b>Cybersecurity Internship Project</b>
</p>

<p>
This project demonstrates the complete security hardening of a previously vulnerable web application. 
All identified vulnerabilities aligned with the <b>OWASP Top 10</b> were analyzed, mitigated, and verified.
</p>

<p>
The system implements secure authentication using JSON Web Tokens (JWT) along with industry-standard security best practices.
</p>

<hr/>

<h2>🎯 Objectives</h2>

<ul>
  <li>Identify OWASP Top 10 vulnerabilities</li>
  <li>Implement secure JWT-based authentication</li>
  <li>Apply password hashing using bcrypt</li>
  <li>Secure HTTP headers using Helmet.js</li>
  <li>Improve input validation and error handling</li>
  <li>Strengthen session and token management</li>
</ul>

<hr/>

<h2>🛠️ Tech Stack</h2>

<ul>
  <li><b>Node.js</b></li>
  <li><b>Express.js</b></li>
  <li><b>JWT (JSON Web Tokens)</b></li>
  <li><b>bcrypt</b></li>
  <li><b>Helmet.js</b></li>
  <li><b>dotenv</b></li>
</ul>

<hr/>

<h2>🔐 Security Enhancements Implemented</h2>

<h3>1️⃣ Authentication & Authorization</h3>
<ul>
  <li>Secure JWT token generation</li>
  <li>Token expiration and validation</li>
  <li>Role-based access control (if implemented)</li>
</ul>

<h3>2️⃣ Password Security</h3>
<ul>
  <li>Password hashing using bcrypt</li>
  <li>Salted hashing</li>
  <li>Secure password comparison</li>
</ul>

<h3>3️⃣ OWASP Top 10 Mitigations</h3>
<ul>
  <li>Injection prevention</li>
  <li>Cross-Site Scripting (XSS) protection</li>
  <li>Cross-Site Request Forgery (CSRF) mitigation</li>
  <li>Secure HTTP headers via Helmet</li>
  <li>Environment variable protection</li>
  <li>Error handling without sensitive data leakage</li>
</ul>

<hr/>

<h2>🚀 Quick Start</h2>

<h3>1️⃣ Clone Repository</h3>

<pre>
git clone https://github.com/Crack329/Secure-JWT-Auth.git
cd Secure-JWT-Auth
</pre>

<h3>2️⃣ Install Dependencies</h3>

<pre>
npm install
</pre>

<h3>3️⃣ Configure Environment Variables</h3>

<pre>
cp .env.example .env
</pre>

<p>Update the <code>.env</code> file:</p>

<pre>
PORT=3000
JWT_SECRET=your_super_secure_secret
</pre>

<h3>4️⃣ Start the Server</h3>

<pre>
node server.js
</pre>

<h3>5️⃣ Open in Browser</h3>

<pre>
http://localhost:3000
</pre>

<p><b>Demo Credentials</b></p>

<pre>
Username: admin
Password: admin123
</pre>

<hr/>

<h2>📂 Project Structure</h2>

<pre>
Secure-JWT-Auth/
│
├── server.js
├── routes/
├── middleware/
├── controllers/
├── models/
├── .env.example
├── package.json
└── README.md
</pre>

<hr/>

<h2>🧪 Testing Security</h2>

<ul>
  <li>Invalid token access</li>
  <li>Expired token behavior</li>
  <li>Password hashing verification</li>
  <li>Unauthorized route access</li>
  <li>Header inspection via browser developer tools</li>
</ul>

<hr/>

<h2>📊 Learning Outcomes</h2>

<ul>
  <li>Practical experience in application security</li>
  <li>OWASP Top 10 remediation techniques</li>
  <li>Secure authentication workflows</li>
  <li>Strengthened backend security architecture</li>
</ul>

<hr/>

<h2>⚠️ Disclaimer</h2>

<p>
This project was developed for educational and internship purposes. 
It demonstrates security best practices but should be further audited before production deployment.
</p>

<hr/>

<hr/>

<h2>👩‍💻 Author</h2>

<p>
<b>Maryam Nasir</b><br/>
Cybersecurity Intern<br/><br/>

🔗 <a href="https://github.com/Crack329" target="_blank">
github.com/Crack329
</a>
</p>


<h2>📜 License</h2>

<p>
This project is licensed under the MIT License.
</p>
