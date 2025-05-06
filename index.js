require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");


const expireTime = 24 * 60 * 60 * 1000; //expires after 1 day  (hours * minutes * seconds * millis)


const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;


var { database } = include('./databaseConnection.js');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore, //default is memory store 
	saveUninitialized: false, 
	resave: true
}
));

app.get('/', (req,res) => {
    if (req.session.authenticated) {
        res.send(`
            <h1>Hello, ${req.session.username}!</h1>
            <a href="/members"><button>Go to Members Area</button></a><br><br>
            <a href="/logout"><button>Log out</button></a>
        `);
    } else {
        res.send(`
            <h1>Welcome!</h1>
            <a href="/createUser"><button>Sign up</button></a>
            <a href="/login"><button>Log in</button></a>
        `);
    }
});

app.get('/nosql-injection', async (req,res) => {
	var username = req.query.user;

	if (!username) {
		res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
		return;
	}
	console.log("user: "+username);

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);

	//If we didn't use Joi to validate and check for a valid URL parameter below
	// we could run our userCollection.find and it would be possible to attack.
	// A URL parameter of user[$ne]=name would get executed as a MongoDB command
	// and may result in revealing information about all users or a successful
	// login without knowing the correct password.
    
	if (validationResult.error != null) {  
	   console.log(validationResult.error);
	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	   return;
	}	

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

	console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

app.get('/about', (req,res) => {
    var color = req.query.color;

    res.send("<h1 style='color:"+color+";'>Patrick Guichon</h1>");
});

app.get('/contact', (req,res) => {
    var missingEmail = req.query.missing;
    var html = `
        email address:
        <form action='/submitEmail' method='post'>
            <input name='email' type='text' placeholder='email'>
            <button>Submit</button>
        </form>
    `;
    if (missingEmail) {
        html += "<br> email is required";
    }
    res.send(html);
});

app.post('/submitEmail', (req,res) => {
    var email = req.body.email;
    if (!email) {
        res.redirect('/contact?missing=1');
    }
    else {
        res.send("Thanks for subscribing with your email: "+email);
    }
});


app.get('/createUser', (req,res) => {
    var html = `
    create user
    <form action='/submitUser' method='post'>
    <input name='username' type='text' placeholder='username' required>
    <input name='email' type='email' placeholder='email' required>
    <input name='password' type='password' placeholder='password' required>
    <button>Submit</button>
    </form>
    `;

    if (req.query.error) {
         html += "<p style='color:red;'>Invalid input. Please check username, email, and password requirements.</p>";
    }
    res.send(html);
});


app.get('/login', (req,res) => {
    var loginError = req.session.loginError;
    delete req.session.loginError;
    var html = `
    log in
    <form action='/loggingin' method='post'>
    <input name='username' type='text' placeholder='username'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;

    if (loginError) {
        html += `<p style='color:red;'>${loginError}</p>`;
    }
    res.send(html);
});

app.post('/submitUser', async (req,res) => {
    var username = req.body.username;
    var email = req.body.email; 
    var password = req.body.password;

   
    const schema = Joi.object(
        {
            username: Joi.string().alphanum().max(20).required(),
            email: Joi.string().email().required(), 
            password: Joi.string().max(20).required()
        });


    const validationResult = schema.validate({username, email, password});
    if (validationResult.error != null) {
       console.log(validationResult.error);
       res.redirect("/createUser?error=1");
       return;
   }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({username: username, email: email, password: hashedPassword});
    console.log("Inserted user");

    var html = `
        <h1>User successfully created!</h1>
        <br>
        <a href="/"><button>Back to Home</button></a>
    `;
    res.send(html);
});

app.post('/loggingin', async (req,res) => {
    var username = req.body.username;
    var password = req.body.password;

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/login");
	   return;
	}

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

	console.log(result);
	if (result.length != 1) {
		console.log("user not found");
        req.session.loginError = 'Invalid username/password combination.';
		res.redirect("/login");
		return;
	}
	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
		req.session.username = username;
		req.session.cookie.maxAge = expireTime;

		res.redirect('/loggedIn');
		return;
	}
	else {
		console.log("incorrect password");
        req.session.loginError = 'Invalid username/password combination.';
		res.redirect("/login");
		return;
	}
});

app.get('/loggedin', (req,res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
        return; 
    }
    var html = `
    <h1>You are logged in! Hello ${req.session.username}</h1>
    <br>
    <a href="/"><button>Back to Home</button></a>
    `;
    res.send(html);
});


app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        return res.redirect('/login');
    }

    const username = req.session.username;
    const catImages = ['b09.png', 'cat2.png', 'exam_2.png']; 
    const randomImage = catImages[Math.floor(Math.random() * catImages.length)];
    var html = `
        <h1>Hello, ${username}!</h1>
        <p>Welcome to the members area.</p>
        <img src="/${randomImage}" alt="Random Cat" style="max-width: 500px; border: 1px solid black;"><br>
        <a href="/logout"><button>Logout</button></a> 
    `;
    res.send(html);
});

app.get('/logout', (req,res) => {
    req.session.destroy(() => {     
        res.redirect('/');
    }); 
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
	res.status(404);
	res.send("Page not found - 404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
});
