const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const mongoose = require('mongoose');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const app = express();
const port = 5000;

// Set EJS as the view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views')); // Specify the views folder

// MongoDB connection
mongoose.connect('mongodb://localhost/file_upload', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log("Connected to MongoDB"))
  .catch((err) => {
    console.log("Failed to connect to MongoDB", err);
  });

// MongoDB user schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  files: [String], // To store file paths associated with the user
});
const User = mongoose.model('User', userSchema);

// Session middleware
app.use(session({
  secret: 'secret',
  resave: false,
  saveUninitialized: true,
}));

// Serve static files (for frontend)
app.use(express.static('public'));

// Body parser for handling JSON and form data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Middleware to check admin authentication
function isAdmin(req, res, next) {
  if (req.session.isAdmin) {
    return next();
  }
  res.status(403).send('Access denied. Admins only.');
}

// Middleware to check user authentication
function isAuthenticated(req, res, next) {
  if (req.session.userId) {
    return next();
  }
  res.redirect('/login');
}

// Routes for serving signup and login pages
app.get('/', (req, res) => {
  res.redirect('/signup');
});

app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Admin login route
app.post('/admin/login', (req, res) => {
  const { username, password } = req.body;

  if (username === 'Admin' && password === '4321') {
    req.session.isAdmin = true;
    req.session.username = 'Admin';
    res.redirect('/admin');
  } else {
    res.status(401).send('Invalid admin credentials');
  }
});

// Admin page route
app.get('/admin', isAdmin, async (req, res) => {
  try {
    const users = await User.find({}, { username: 1, _id: 0 });
    const userData = users.map(user => {
      const userFolder = path.join(__dirname, 'uploads', user.username);
      const files = fs.existsSync(userFolder) ? fs.readdirSync(userFolder) : [];
      return { username: user.username, files };
    });

    // Render admin.ejs with dynamic user data
    res.render('admin', { users: userData });
  } catch (err) {
    console.error('Error fetching users:', err);
    res.status(500).send('Failed to fetch user data');
  }
});

// Fetch all users and their uploaded files
app.get('/admin/users', isAdmin, async (req, res) => {
  try {
    const users = await User.find({}, { username: 1, _id: 0 });
    const userData = users.map(user => {
      const userFolder = path.join(__dirname, 'uploads', user.username);
      const files = fs.existsSync(userFolder) ? fs.readdirSync(userFolder) : [];
      return { username: user.username, files };
    });
    res.json(userData);
  } catch (err) {
    console.error('Error fetching users:', err);
    res.status(500).send('Failed to fetch user data');
  }
});

// Delete a user and their files
app.delete('/admin/delete-user/:username', isAdmin, async (req, res) => {
  const { username } = req.params;

  try {
    const user = await User.findOneAndDelete({ username });
    if (!user) {
      return res.status(404).send('User not found');
    }

    const userFolder = path.join(__dirname, 'uploads', username);
    if (fs.existsSync(userFolder)) {
      fs.rmSync(userFolder, { recursive: true, force: true });
    }

    res.status(200).send('User and their files deleted successfully');
  } catch (err) {
    console.error('Error deleting user:', err);
    res.status(500).send('Failed to delete user');
  }
});

// User signup
app.post('/signup', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send('Username and password are required.');
  }

  try {
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).send('Username already taken');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();

    const userFolder = path.join(__dirname, 'uploads', username);
    if (!fs.existsSync(userFolder)) {
      fs.mkdirSync(userFolder, { recursive: true });
    }

    res.redirect('/login');
  } catch (err) {
    console.error('Error during signup:', err);
    res.status(500).send('Server error during signup.');
  }
});

// User login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send('Username and password are required.');
  }

  try {
    if (username === 'Admin' && password === '4321') {
      req.session.isAdmin = true;
      req.session.username = 'Admin';
      return res.redirect('/admin');
    }

    const user = await User.findOne({ username });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).send('Invalid credentials');
    }

    req.session.userId = user._id;
    req.session.username = user.username;
    res.redirect('/home');
  } catch (err) {
    console.error('Error during login:', err);
    res.status(500).send('Server error during login.');
  }
});

// User home
app.get('/home', isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'home.html'));
});

// User logout
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).send('Failed to log out');
    }
    res.redirect('/login');
  });
});

// File upload functionality
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const userFolder = path.join(__dirname, 'uploads', req.session.username);
    if (!fs.existsSync(userFolder)) {
      fs.mkdirSync(userFolder, { recursive: true });
    }
    cb(null, userFolder);
  },
  filename: (req, file, cb) => {
    cb(null, file.originalname);
  }
});

const upload = multer({ storage });

// Fetch files for a user
app.get('/files', isAuthenticated, (req, res) => {
  const userFolder = path.join(__dirname, 'uploads', req.session.username);
  fs.readdir(userFolder, (err, files) => {
    if (err) {
      return res.status(500).send('Unable to fetch files');
    }
    res.json(files);
  });
});

// Upload a file
app.post('/upload', upload.single('file'), isAuthenticated, (req, res) => {
  if (!req.file) {
    return res.status(400).send('No file uploaded');
  }
  res.json({ message: 'File uploaded successfully' });
});

// Delete a file by admin
app.delete('/admin/delete-file/:username/:filename', isAdmin, (req, res) => {
  const { username, filename } = req.params;
  const filePath = path.join(__dirname, 'uploads', username, filename);

  fs.unlink(filePath, (err) => {
    if (err) {
      return res.status(500).json({ message: 'Error deleting file' });
    }
    res.json({ message: 'File deleted successfully' });
  });
});


// Start the server
app.listen(port, '0.0.0.0', () => {
  console.log(`Server running at http://<your-ip>:${port}`);
});
