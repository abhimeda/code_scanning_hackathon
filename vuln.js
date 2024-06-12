var express = require('express');
var app = express();
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');

app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());

app.get('/', function (req, res) {
    // Vulnerability
    res.sendFile(__dirname + '/index.html');
});

app.listen(3000, function () {
    console.log('App listening on port 3000');
});  

app.post('/login', function (req, res) {
    var username = req.body.username;
    var password = req.body.password;
 
    // Vulnerability
    console.log(`U:${username}  P:${password}`);
    if (username == 'admin' && password == 'password') {
        res.cookie('session', '123456', { httpOnly: false });
        res.redirect('/dashboard');
    } else {
        res.send('Invalid username or password');
    }
});

app.post('/search', function (req, res) {
    var searchQuery = req.body.query;
    // Vulnerability
    var regex = new RegExp(searchQuery);
 
    // Simulated data  
    var data = ['John', 'Jane', 'Doe', 'Smith', 'Admin'];
 
    var results = data.filter(function (item) {
        return regex.test(item);
    });
 
    res.send(results);
});