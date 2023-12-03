const express = require('express');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const service = require('./backend_func');

const app = express();
const port = 7777;
const upload = multer({ dest: '~/' });

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.set('view engine', 'ejs'); // Set EJS as the view engine
app.set('views', __dirname + '/views'); // Specify the directory where your views/templates are located


app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});

//Home route
app.get('/', service.isHomeAuthenticated);

// Registration route
app.post('/registerForm', service.register);

// Registration route
app.get('/register', service.getRegisterPage);

// Login route
app.post('/loginForm', service.login);

// getLoginPage route
app.get('/login', service.getLoginPage);

//Create File route
app.post('/create', service.isAuthenticated, upload.single('uploadedFile'), service.createFile)

//List File route
app.get('/list', service.isAuthenticated, service.listFile)

//List File route
app.get('/logout', service.logout)

//Delete File route
app.post('/delete', service.isAuthenticated, service.deleteFile)