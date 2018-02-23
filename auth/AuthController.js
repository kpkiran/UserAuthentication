var express = require("express");
var router = express.Router();
var bodyParser = require("body-parser");
var jwt = require("jsonwebtoken");
var bcrypt = require("bcryptjs");

var config = require("../config");
var User = require("../user/User");

router.use(bodyParser.urlencoded({ extended: false }));
router.use(bodyParser.json());

router.post('/register', (req, res) => {
    var hashpassword = bcrypt.hashSync('req.body.password', 8);
    console.log(hashpassword);
    User.create({
            name: req.body.name,
            email: req.body.email,
            password: hashpassword
        },
        (err, user) => {
            if (err)
                return res
                    .status(500)
                    .send("There was a problem creating the user");
            console.log(user.name, user.email, user.password);
            var token = jwt.sign({ id: user._id }, config.secret);
            res.status(200).send({ auth: true, token: token });
        }
    );
});

router.get('/me', (req, res) => {
    var token = req.headers['x-access-token'];
    if (!token) return res.status(401).send({ auth: false, message: 'Authentication failed. No token provided' });

    jwt.verify(token, config.secret, (err, decoded) => {
        if (err) return res.status(404).send({ auth: false, message: 'Failed to authenticate' });

        User.findById(decoded.id, { 'password': 0 }, (err, user) => {
            if (err) return res.status(500).send("There was a problem finding the user.")

            if (!user) return res.status(404).send("No user found");

            res.status(200).send(user);
        });
    });
});

router.post('/login', (req, res) => {

    User.findOne({ email: req.body.email }, (err, user) => {
        if (err) return res.status(500).send({ auth: false, message: 'Error on the server' });
        if (!user) return res.status(404).send({ auth: false, message: 'Unable to find the user' });

        var passwordIsValid = bcrypt.compare('req.body.password', 'user.password');

        if (!passwordIsValid) return res.status(400).send({ auth: false, message: 'Password did not match. Unable to authorize.' });

        var token = jwt.sign({ id: user._id }, config.secret);

        res.status(200).send({ auth: true, token: token });

    });
});

router.post('/logout', (req, res) => {
    res.status(200).send({ auth: false, token: null });
});

module.exports = router;