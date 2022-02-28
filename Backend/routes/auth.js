const express = require('express');
const User = require('../models/User');
const router = express.Router();
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { json } = require('express');
const fetchuser = require('../middleware/fetchuser');

const JWT_SECRET = 'Harryisagoodb$oy';


// Route 1: Creat a User using: POST "/api/auth/createuser". No login required
router.post('/createuser', [
    body('name', 'Enter the valid name' ).isLength({ min: 3 }),
    body('email', 'Enter the valid email').isEmail(),
    body('password', 'Password at least must be 5 charactors').isLength({ min: 5 }), 
], async (req, res)=>{
    let success = false;
    // If there are errors, return Bad request and the errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success, errors: errors.array() });
    }
    
    try {
     // Check whether the user this email exists alread   
   
    let user = await User.findOne({email: req.body.email});
    if(user){
        return res.status(400).json({success, error: "Sorry a user with this already exits"})
    }
    const salt = await bcrypt.genSalt(10);
    const secPass = await bcrypt.hash(req.body.password, salt);
    // Create a new user
    user = await User.create({
        name: req.body.name,
        email: req.body.email,
        password: secPass,

      });
      const data = {
          user:{
              id: user.id
          }
      }

      const authtoken = jwt.sign(data, JWT_SECRET);

    //res.json(user)
    success = true;
    res.json({success, authtoken})

}   catch (error) {
    console.error(error.message);
    res.status(500).send("Internal Server Error");
}
})

// Route 2: Authenticate a User using: POST "/api/auth/login". No login required
router.post('/login', [
    body('email', 'Enter the valid email').isEmail(),
    body('password', 'Password can not be blank').exists(), 
], async (req, res)=>{
    let success = false;
// If there are errors, return Bad request and the errors
const errors = validationResult(req);
if (!errors.isEmpty()) {
  return res.status(400).json({ errors: errors.array() });
}

const {email, password} = req.body;
try {
    let user = await User.findOne({email});
    if (!user){
        success = false
        return res.status(400).json({error: "please try to login with correct Credentials "});
    }

    const passwordCompare = await bcrypt.compare(password, user.password);
    if(!passwordCompare){
        success = false
        return res.status(400).json({success, error: "please try to login with correct Credentials "});
    }

    const data = {
        user:{
            id: user.id
        }
    }

    const authtoken = jwt.sign(data, JWT_SECRET);
    success = true;
    res.json({success, authtoken})

} catch (error) {
    console.error(error.message);
    res.status(500).send("Internal Server Error");
}

})

// Route 3: Get Loggedin User Details Using: POST "/api/auth/getuser". Login required
router.post('/getuser', fetchuser, async (req, res)=>{
try {
    userId = req.user.id;
    const user = await User.findById(userId).select("-password")
    res.send(user)
} catch (error) {
    console.error(error.message);
    res.status(500).send("Internal Server Error");
}
})
module.exports = router