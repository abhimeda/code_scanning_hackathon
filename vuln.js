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
