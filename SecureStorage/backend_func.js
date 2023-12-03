const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const { exec } = require('child_process');

require('dotenv').config();

const secretKey = process.env.JWTSECRET
const connectionString = process.env.PSQL_CONNURL
const pool = new Pool({
  connectionString
})


async function isAuthenticated(req, res, next){
  try{
    //Token from cookie
    const token = req.cookies.token;
    if(token === undefined)
      throw new Error("Authentication failed")

    //Decode token
    const tokenDecode = jwt.verify(token, secretKey);
    if(tokenDecode === undefined)
      throw new Error("Authentication failed")

    const result = await pool.query('SELECT username FROM users WHERE username = $1', [tokenDecode.username]);
    if (result.rows.length === 0)
      throw new Error("Authentication failed")

    next();
  }
  catch(error){
    res.redirect('/')
  }
}

async function isHomeAuthenticated(req, res, next){
  try{
    //Token from cookie
    const token = req.cookies.token;
    if(token === undefined)
      throw new Error

    //Decode token
    const tokenDecode = jwt.verify(token, secretKey);
    if(tokenDecode === undefined)
      throw new Error

    const result = await pool.query('SELECT username FROM users WHERE username = $1', [tokenDecode.username]);
    if (result.rows.length === 0)
      throw new Error

    res.redirect('/list');
  }
  catch(error){
    const localUrl = `${req.protocol}://${req.get('host')}`;
    res.status(200).render('index', { localUrl }); //FRONTEND
  }
}

async function getRegisterPage(req, res){
  const localUrl = `${req.protocol}://${req.get('host')}`;
  res.status(200).render('register', {csrfToken: req.csrfToken(), localUrl})
}

async function register(req, res){
  const { username, password } = req.body;

  try {
    //Check if the username is already taken
    const userExists = await pool.query('SELECT * FROM users WHERE username = $1', [username]);

    //error: username already taken
    if (userExists.rows.length > 0)
      throw new Error('Username already taken'); //FRONTEND

    //SECURE
    // Minimum eight characters, at least one uppercase letter, one lowercase letter, one number, and one special character
    const strongPasswordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{6,}$/;
    const isStrong = strongPasswordRegex.test(password);
    if(!isStrong)
      throw new Error('Password should at least have 1 letter, 1 digit, and have 6 characters in total')
    
    //Hash the password before storing it in the database
    const hashedPassword = await bcrypt.hash(password, 10);

    //Insert the new user into the database
    await pool.query('INSERT INTO users (username, password) VALUES ($1, $2)', [username, hashedPassword]);
    
    //Succesful response
    const message = "Registration succesful";
    const localUrl = `${req.protocol}://${req.get('host')}`;
    res.status(200).render('success', { message, localUrl })
  } 
  catch (error) {
    const redirect = "/register";
    const localUrl = `${req.protocol}://${req.get('host')}`;
    res.status(500).render('error', { redirect, error, localUrl })
  }
}

async function login(req, res){
  const { username, password } = req.body;

  try {
    if(
      (username === undefined || password === undefined) ||
      (username === null || password === null)
    ){
      throw new Error('Please fill all of the form')
    }

    //SECURE ALREADY
    //Query user data from db
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);

    //error: username not found
    if (result.rows.length === 0)
      throw new Error('Login Unsuccesful'); //FRONTEND
    
    //Compare the provided password with the hashed password in the database
    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);

    //error: password not match
    if (!match) 
      throw new Error('Login Unsuccesful'); //FRONTEND
    
    //Generate a JWT token
    const token = jwt.sign({ username: user.username }, secretKey, { expiresIn: '1h' });

    //Set the session token in a cookie
    res.cookie('token', token, 
    { httpOnly: true, 
      maxAge: 1800000,
      sameSite: 'Strict' //SECURE
    }); 
  
    //Succesful response
    res.redirect('/'); //FRONTEND
  } 
  catch (error) {
    const redirect = "/login";
    const localUrl = `${req.protocol}://${req.get('host')}`;
    res.status(500).render('error', { redirect, error, localUrl })
  }
}

async function getLoginPage(req, res){
  const localUrl = `${req.protocol}://${req.get('host')}`;
  res.status(200).render('login.ejs', {csrfToken: req.csrfToken(), localUrl}); //FRONTEND
}

async function createFile(req, res){
  const tokenDecoded = jwt.verify(req.cookies.token, secretKey)
  const uploadedFile = req.file
  
  try{
    //If filename is empty  
    if(uploadedFile === undefined)
      throw new Error("No file!") //FRONTEND
    
    await pool.query('INSERT INTO files (uid, filename, file_owner) VALUES ($1, $2, $3)',
      [uploadedFile.filename, uploadedFile.originalname, tokenDecoded.username]
    );

    const message = "File uploaded succesfuly";
    const localUrl = `${req.protocol}://${req.get('host')}`;
    res.status(200).render('success', { message, localUrl })
  }
  catch(error){
    const redirect = "/";
    const localUrl = `${req.protocol}://${req.get('host')}`;
    res.status(500).render('error', { redirect, error, localUrl })
  }
}

//List File route
async function listFile(req, res){
  const username = jwt.verify(req.cookies.token, secretKey).username

  try{
    const query = await pool.query(
      'SELECT uid, filename, upload_date FROM files WHERE file_owner = $1',
      [username]
    );

    const result = query.rows
    const csrfToken = req.csrfToken()
    const localUrl = `${req.protocol}://${req.get('host')}`;
    res.render('list', { username, result, csrfToken, localUrl }) //FRONTEND
  }
  catch(error){
    res.cookie('token', '', { expires: new Date(0) });
    res.redirect('/')
  }
}

async function deleteFile(req, res){
  const { uid } = req.body
  const tokenDecoded = jwt.verify(req.cookies.token, secretKey)

  try{
    const uid_regex=/^[a-z0-9]+$/ //SECURE
    if(!uid_regex.test(uid))
      throw new Error("Input malformed");

    const result = await pool.query(
      'SELECT * FROM files WHERE uid = $1 AND file_owner = $2',
      [uid, tokenDecoded.username]
    );
    
    if(result.rows.length === 0)
      throw new Error("File not found!")    //FRONTEND

    exec('ls ~/' + uid, (error, stdout, stderr) => {
      console.log(stdout)
      return
    })   

    await pool.query(
      'DELETE FROM files WHERE uid = $1',
      [uid]
    );
    
    const message = "File succesfuly deleted"
    const localUrl = `${req.protocol}://${req.get('host')}`;
    res.status(200).render('success', { message, localUrl })

  }
  catch(error){
    const redirect = "/";
    const localUrl = `${req.protocol}://${req.get('host')}`;
    res.status(500).render('error', { redirect, error, localUrl })
  }
}

async function logout(req, res){
  res.clearCookie('token');

  // Redirect or send any other response as needed
  res.redirect('/');
}

module.exports = {
  isHomeAuthenticated,
  isAuthenticated,
  register,
  getRegisterPage,
  login,
  getLoginPage,
  createFile,
  listFile,
  deleteFile,
  logout
}