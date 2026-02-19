require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const multer = require('multer');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));

// Database
mongoose.connect(process.env.MONGO_URI)
.then(()=>console.log("MongoDB Connected"));

// Models
const Member = mongoose.model('Member',{
 plan:String,
 name:String,
 email:String,
 image:String,
 created:{type:Date,default:Date.now}
});

const Admin = mongoose.model('Admin',{
 email:String,
 password:String
});

// Upload
const storage = multer.diskStorage({
 destination:'uploads/',
 filename:(req,file,cb)=>{
  cb(null,Date.now()+file.originalname);
 }
});

const upload = multer({storage});

// Email
const transporter = nodemailer.createTransport({
 service:'gmail',
 auth:{
  user:process.env.ADMIN_EMAIL,
  pass:process.env.ADMIN_PASS
 }
});

// Create Admin (Run Once)
app.post('/api/setup', async(req,res)=>{
 const hash = await bcrypt.hash('admin123',10);
 await Admin.create({
  email:'admin@fanclub.com',
  password:hash
 });
 res.json({msg:'Admin Created'});
});

// Login
app.post('/api/login', async(req,res)=>{
 const {email,password}=req.body;
 const admin = await Admin.findOne({email});

 if(!admin) return res.status(400).json({msg:'No user'});

 const ok = await bcrypt.compare(password,admin.password);
 if(!ok) return res.status(400).json({msg:'Wrong pass'});

 const token = jwt.sign({id:admin._id},process.env.JWT_SECRET);
 res.json({token});
});

// Middleware
function auth(req,res,next){
 const token=req.headers.authorization;
 if(!token) return res.sendStatus(401);

 try{
  jwt.verify(token,process.env.JWT_SECRET);
  next();
 }catch{
  res.sendStatus(403);
 }
}

// Membership
app.post('/api/membership',upload.single('giftcard'), async(req,res)=>{

 const {plan,name,email}=req.body;
 const file=req.file;

 const member = await Member.create({
  plan,name,email,
  image:file.filename
 });

 // Send Email
 await transporter.sendMail({
  from:process.env.ADMIN_EMAIL,
  to:process.env.ADMIN_EMAIL,
  subject:'New Membership',
  text:`Plan:${plan}\nName:${name}\nEmail:${email}`,
  attachments:[
   {
    filename:file.filename,
    path:'uploads/'+file.filename
   }
  ]
 });

 res.json({success:true});
});

// Admin Panel
app.get('/api/members',auth, async(req,res)=>{
 const data = await Member.find().sort({created:-1});
 res.json(data);
});

app.listen(process.env.PORT,()=>{
 console.log("Server running");
});
