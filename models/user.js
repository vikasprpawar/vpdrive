// models/User.js
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  files: [String],  // Array to store uploaded file names
});

const User = mongoose.model('User', userSchema);
module.exports = User;
