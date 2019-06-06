const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');

const db = require('./data/dbConfig');
const Users = require('./users/users-model.js');


const server = express();

server.use(helmet());
server.use(cors());
server.use(express.json());

server.get('/', (req, res) => {
    res.send('It works for now');
});

server.post('/api/register', (req, res) => {
    let user = req.body;

    if(!user.username || !user.password) {
        return res.status(500).json({ message: 'Need username and password!' });
    }

    if(user.password.length < 8) {
        return res.status(400).json({ message: 'Password too short!' });
    }

    const hash = bcrypt.hashSync(user.password, 14);
    user.password = hash;

    Users.add(user)
        .then(saved => {
            res.status(201).json(saved);
        })
        .catch(err => {
            res.status(500).json(err);
        });
});

server.post('/api/login', (req, res) => {
    let { username, password } = req.body;

    Users.findBy({ username })
        .first()
        .then(user => {
            const isValid = bcrypt.compareSync(password, user.password);

            if(user && isValid) {
                res.status(200).json({ message: `Welcome ${user.username}!` });
            } else {
                res.status(401).json({ message: 'Invalid Credentials' });
            }
        })
        .catch(err => {
            res.status(500).json(err);
        });
});

server.get('/api/users', authorize, (req, res) => {
    Users.find()
        .then(users => {
            res.json(users);
        })
        .catch(err => {
            res.send(err);
        });
});

function authorize(req, res, next) {
    const username = req.headers['x-username'];
    const password = req.headers['x-password'];

    if(!username || !password) {
        return res.status(401).json({ message: 'Invalid Credentials' });
    }

    Users.findBy({ username })
        .first()
        .then(user => {
            if(user && bcrypt.compareSync(password, user.password)) {
                next();
            } else {
                res.status(401).json({ message: 'Invalid Credentials' });
            }
        })
        .catch(err => {
            res.status(500).json(err);
        });
}

const port = process.env.PORT || 5555;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
