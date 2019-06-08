const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');

const session = require('express-session');
const SessionStore = require('connect-session-knex')(session);

// const db = require('./data/dbConfig');
const Users = require('./users/users-model.js');


const server = express();

const sessionConfig = {
    name: 'osiris',
    secret: 'who are you',
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 60 * 60 * 1000,
        secure: false,
        httpOnly: true,
    },
    store: new SessionStore({
        knex: require('./data/dbConfig'),
        tablename: 'sessions',
        sidfieldname: 'sid',
        createtable: true,
        clearInterval: 60 * 60 * 1000,
    }),
}

server.use(session(sessionConfig));
server.use(helmet());
server.use(express.json());
server.use(cors());

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
                req.session.user = user;

                res.status(200).json({ message: `Welcome ${user.username}! User ${user.id} is logged in` });
            } else {
                res.status(401).json({ message: 'You shall not pass' });
            }
        })
        .catch(err => {
            res.status(500).json(err);
        });
});

server.get('/api/users', restricted, (req, res) => {
    Users.find()
        .then(users => {
            if(!users) {
                res.status(401).json({ message: 'You shall not pass' });
            } else {
                res.json(users);
            }
            
        })
        .catch(err => {
            res.send(err);
        });
});

server.get('/api/logout', restricted, (req, res) => {
    req.session.destroy((err) => {
        if(err) {
            console.log(err);
            res.status(500).json({ message: 'There was an error!' });
        }

        res.end();
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

function restricted(req, res, next) {
    if(req.session && req.session.user) {
        next();
    } else {
        res.status(401).json({ message: 'You shall not pass' });
    }
}

const port = process.env.PORT || 5555;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
