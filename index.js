const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');

const db = require('./data/dbConfig');
const Users = require('./users/users-model');


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

const port = process.env.PORT || 5555;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
