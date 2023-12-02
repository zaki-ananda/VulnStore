const express = require('express');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const service = require('./backend_func');
const csrf = require('csurf')
const rateLimit = require('express-rate-limit');

const app = express();
const port = 7777;
const upload = multer({ dest: '/home/airev/' });

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.set('view engine', 'ejs'); // Set EJS as the view engine
app.set('views', __dirname + '/views'); // Specify the directory where your views/templates are located

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 7, // 7 attempts per windowMs
  message: 'Too many login attempts from this IP, please try again after 15 minutes',
});

var csrfProtection = csrf({ cookie: true })
//Create File route
app.post('/create', service.isAuthenticated, upload.single('uploadedFile'), csrfProtection, service.createFile)

app.use(csrf({ cookie: true }))

//Home route
app.get('/', service.isHomeAuthenticated);

// Registration route
app.post('/registerForm', service.register);

// Registration route
app.get('/register', service.getRegisterPage);

// Login route
app.post('/loginForm', service.login);

// getLoginPage route
app.get('/login', loginLimiter, service.getLoginPage);

//List File route
app.get('/list', service.isAuthenticated, service.listFile)

//Logout File route
app.get('/logout', service.logout)

//Delete File route
app.post('/delete', service.isAuthenticated, service.deleteFile)

app.use(function (err, req, res, next) {
  if (err.code !== 'EBADCSRFTOKEN') return next(err)
  const error = new Error('Bad CSRF Token. Please try again')
  res.status(500).render('error', { redirect: '/', error})
})

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});