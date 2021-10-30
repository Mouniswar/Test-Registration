const express = require('express');
const app = express();
const db = require('./db/mongodb');

app.use(express.json());
const port = process.env.PORT || 3000;


db.connectToServer( function( err) {
    if (err) console.log(err);
  
    const userRouter = require('./routes/UserController');

    app.use(userRouter);
    app.listen(3000, function () { console.log('Server is running on port 3000.')})
});